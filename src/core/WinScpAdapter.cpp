#include "WinScpAdapter.h"
#include "SftpClient.h"
#include "global.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "ImportIoUtil.h"
#include "UnicodeHelpers.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <string>

namespace sftp {

namespace {

// Registry root the install-mode WinSCP writes to. Every session key sits
// under HKCU\Software\Martin Prikryl\WinSCP 2\Sessions\<url-encoded name>.
constexpr const char* kWinScpSessionsRoot =
    "Software\\Martin Prikryl\\WinSCP 2\\Sessions";

// Portable WinSCP.ini prefixes session names with this literal.
constexpr const char* kIniSessionsPrefix = "Sessions\\";

// WinSCP MungeStr charset — every byte in this set is percent-encoded on
// disk (registry subkey name or INI section suffix):
//   0x00..0x1F                     control bytes
//   0x7F..0xFF                     DEL and every non-ASCII byte (so UTF-8
//                                  bytes in international session names
//                                  round-trip as %XX pairs)
//   ' '                            space (visible as %20 in "Default%20Settings")
//   '%'                            self-escape so UrlDecode round-trips
//   '\\'                           registry subkey separator
//   '/'                            folder separator inside a workspace path
//   '*' '?' '"' '<' '>' '|'        NTFS-illegal filename chars
//   leading '.'                    registry subkey rule
// Anything outside the set (printable ASCII except the above) passes through.
std::string UrlEncode(const std::string& raw)
{
    std::string out;
    out.reserve(raw.size());
    for (size_t i = 0; i < raw.size(); ++i) {
        const unsigned char ch = static_cast<unsigned char>(raw[i]);
        const bool needsEscape =
            ch < 0x20 || ch >= 0x7F ||
            ch == ' '  || ch == '%'  || ch == '\\' || ch == '/' ||
            ch == '*'  || ch == '?'  || ch == '"'  ||
            ch == '<'  || ch == '>'  || ch == '|'  ||
            (i == 0 && ch == '.');
        if (!needsEscape) {
            out.push_back(static_cast<char>(ch));
        } else {
            char buf[4];
            std::snprintf(buf, sizeof(buf), "%%%02X", ch);
            out.append(buf);
        }
    }
    return out;
}

// GetPrivateProfileString wrapper that returns "" when the key is missing
// (Win32 default_value semantics) so callers can test empty-string as absent.
// WinSCP.ini is WinSCP's file, so the Windows profile API reads it; path,
// section and result are UTF-8 like everything else in the adapter.
std::string ReadIniString(const std::string& iniPath, const std::string& section,
                          const char* key)
{
    std::array<wchar_t, 4096> buf{};
    GetPrivateProfileStringW(unicode_util::utf8_to_wstring(section).c_str(),
        unicode_util::utf8_to_wstring(key).c_str(), L"",
        buf.data(), static_cast<DWORD>(buf.size() - 1),
        Utf8PathToWide(iniPath).c_str());
    return unicode_util::wstring_to_utf8(buf.data());
}

// GetPrivateProfileInt with default -1 so callers can distinguish "absent"
// from "present and zero".
int ReadIniDword(const std::string& iniPath, const std::string& section,
                  const char* key)
{
    return GetPrivateProfileIntW(unicode_util::utf8_to_wstring(section).c_str(),
        unicode_util::utf8_to_wstring(key).c_str(), -1,
        Utf8PathToWide(iniPath).c_str());
}

// A session name in UTF-8 back to the encoded name it is stored under.
// WinSCP encodes UTF-8 bytes; an old ANSI configuration encodes the system
// codepage, so both spellings are candidates. A session in a folder is
// stored as "folder/name" with the '/' kept, so each spelling is also tried
// with "%2F" turned back into '/'.
std::vector<std::string> SubKeyNames(const std::string& utf8Name)
{
    std::vector<std::string> out;
    const auto add = [&out](std::string key) {
        if (std::find(out.begin(), out.end(), key) == out.end())
            out.push_back(key);
        for (size_t pos = 0; (pos = key.find("%2F", pos)) != std::string::npos; )
            key.replace(pos, 3, "/");
        if (std::find(out.begin(), out.end(), key) == out.end())
            out.push_back(std::move(key));
    };
    add(UrlEncode(utf8Name));
    add(UrlEncode(unicode_util::wide_to_narrow(
        unicode_util::utf8_to_wstring(utf8Name), CP_ACP)));
    return out;
}

// FSProtocol numeric enum stored in WinSCP session data:
//   0 = SCP-only     — SCP transport, no SFTP fallback
//   1 = SFTP         — SFTP with SCP fallback if the server rejects the subsystem
//   2 = SFTP-only    — SFTP transport only
//   5 = FTP          — plain FTP or FTPS (not supported by this plugin)
//   6 = WebDAV       — not supported
//   7 = S3           — not supported
// Absent value is treated as SFTP (WinSCP's default when the New Site dialog
// is used without touching advanced options).
enum class FsProtoResult { UseSftp, UseScp, Unsupported };

FsProtoResult ClassifyFsProto(int fsProto) noexcept
{
    switch (fsProto) {
        case 0:  return FsProtoResult::UseScp;   // SCP-only
        case 1:  return FsProtoResult::UseSftp;  // SFTP with SCP fallback
        case 2:  return FsProtoResult::UseSftp;  // SFTP-only
        default: return FsProtoResult::Unsupported;  // FTP / WebDAV / S3 / future
    }
}

}  // namespace

bool WinScpAdapter::DetectStandard() const noexcept
{
    HKEY key = nullptr;
    LONG rc = RegOpenKeyExA(HKEY_CURRENT_USER, kWinScpSessionsRoot,
                             0, KEY_READ, &key);
    if (rc != ERROR_SUCCESS) return false;
    RegCloseKey(key);
    return true;
}

std::string WinScpAdapter::ChangeStamp() const
{
    return RegistryChangeStamp(kWinScpSessionsRoot);
}

std::string WinScpAdapter::CustomPathStamp(const std::string& path) const
{
    return FileChangeStamp({ Utf8PathToWide(path) });
}

EnumerationResult WinScpAdapter::EnumerateStandard()
{
    EnumerationResult r;

    HKEY root = nullptr;
    LONG rc = RegOpenKeyExA(HKEY_CURRENT_USER, kWinScpSessionsRoot,
                             0, KEY_READ, &root);
    if (rc != ERROR_SUCCESS) {
        SFTP_LOG("WINSCP", "EnumerateStandard: sessions root open failed rc=%ld", rc);
        r.status = EnumerationStatus::Unreachable;
        return r;
    }

    DWORD index = 0;
    int filtered = 0;
    for (;;) {
        std::array<char, 512> nameBuf{};
        DWORD nameLen = static_cast<DWORD>(nameBuf.size());
        rc = RegEnumKeyExA(root, index, nameBuf.data(), &nameLen,
                            nullptr, nullptr, nullptr, nullptr);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        ++index;
        if (rc != ERROR_SUCCESS) continue;

        // Skip well-known non-session subkeys under Sessions\:
        //   Default Settings / Default%20Settings — template fallbacks
        //   Workspaces                              — per-workspace window layout
        if (_stricmp(nameBuf.data(), "Default%20Settings") == 0 ||
            _stricmp(nameBuf.data(), "Default Settings")   == 0 ||
            _stricmp(nameBuf.data(), "Workspaces")         == 0) { ++filtered; continue; }

        ExternalSessionEntry e;
        e.displayName  = DecodedNameToUtf8(PuttyUrlDecode(std::string(nameBuf.data(), nameLen)));
        e.sourceOrigin = "standard";
        r.sessions.push_back(std::move(e));
    }
    RegCloseKey(root);
    SFTP_LOG("WINSCP", "EnumerateStandard done: sessions=%zu filtered=%d",
             r.sessions.size(), filtered);

    r.status = r.sessions.empty()
        ? EnumerationStatus::OkEmpty
        : EnumerationStatus::OkWithSessions;
    return r;
}

EnumerationResult WinScpAdapter::EnumerateCustomPath(const std::string& path)
{
    EnumerationResult r;

    // Sanity — the picker should already have filtered to `WinSCP.ini`,
    // but reject unreadable paths (missing file, protected folder)
    // upfront so the channel reports Unreachable rather than the caller
    // getting a mysterious OkEmpty.
    const DWORD attrs = GetFileAttributesW(Utf8PathToWide(path).c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        r.status = EnumerationStatus::Unreachable;
        return r;
    }

    // Enumerate every section name in the INI, keep only those matching
    // "Sessions\<name>". GetPrivateProfileSectionNames returns a
    // double-NUL-terminated block and reports size - 2 when it had to cut
    // it, so the buffer grows until the whole list fits.
    const std::wstring widePath = Utf8PathToWide(path);
    std::vector<wchar_t> sectBuf(65536);
    DWORD gotLen = 0;
    for (;;) {
        gotLen = GetPrivateProfileSectionNamesW(
            sectBuf.data(), static_cast<DWORD>(sectBuf.size()), widePath.c_str());
        if (gotLen + 2 < sectBuf.size() || sectBuf.size() >= 16u * 1024 * 1024)
            break;
        sectBuf.assign(sectBuf.size() * 2, L'\0');
    }
    if (gotLen == 0) {
        r.status = EnumerationStatus::OkEmpty;
        return r;
    }

    const size_t prefixLen = std::strlen(kIniSessionsPrefix);
    const wchar_t* p = sectBuf.data();
    while (*p) {
        const std::string section = unicode_util::wstring_to_utf8(p);
        p += wcslen(p) + 1;

        if (section.size() <= prefixLen) continue;
        if (_strnicmp(section.c_str(), kIniSessionsPrefix, prefixLen) != 0)
            continue;

        const std::string keyName = section.substr(prefixLen);
        if (keyName.empty()) continue;
        // Any remaining `\` inside the tail means a nested subsection like
        // `Sessions\Workspaces\<name>\<row>` — WinSCP stores per-workspace
        // window layout there, never a real session.
        if (keyName.find('\\') != std::string::npos) continue;
        if (_stricmp(keyName.c_str(), "Default Settings") == 0 ||
            _stricmp(keyName.c_str(), "Default%20Settings") == 0)
            continue;

        ExternalSessionEntry e;
        e.displayName  = DecodedNameToUtf8(PuttyUrlDecode(keyName));
        e.sourceOrigin = path;
        r.sessions.push_back(std::move(e));
    }

    r.status = r.sessions.empty()
        ? EnumerationStatus::OkEmpty
        : EnumerationStatus::OkWithSessions;
    return r;
}

bool WinScpAdapter::LoadSettings(const ExternalSessionEntry& entry,
                                  pConnectSettings out,
                                  SessionDependency* dependency)
{
    if (!out) return false;

    SFTP_LOG("WINSCP", "LoadSettings display='%s'", entry.displayName.c_str());

    std::string host, userName, keyFile;
    DWORD port = 0, useAgent = 0, fsProtoRaw = 0;
    bool  hasPort = false, hasFsProto = false;
    // WinSCP's tunnel is an SSH session in front of the host, which is what
    // the plugin's jump host is.
    std::string tunnelHost, tunnelUser, tunnelKey;
    DWORD tunnel = 0, tunnelPort = 0, proxyMethod = 0;

    // WinSCP stores a session's keys only where they differ from its
    // "Default Settings"; a key the session lacks has that one's value. A
    // proxy or tunnel set there applies to every session that does not say
    // otherwise, so missing keys are looked up there before being taken as
    // absent.
    if (entry.sourceOrigin == "standard") {
        HKEY key = nullptr;
        for (const auto& name : SubKeyNames(entry.displayName)) {
            const std::string subKey = std::string(kWinScpSessionsRoot) + "\\" + name;
            if (RegOpenKeyExA(HKEY_CURRENT_USER, subKey.c_str(), 0, KEY_READ, &key) == ERROR_SUCCESS)
                break;
            key = nullptr;
        }
        if (!key) return false;
        HKEY defaults = nullptr;
        for (const char* name : { "Default%20Settings", "Default Settings" }) {
            const std::string subKey = std::string(kWinScpSessionsRoot) + "\\" + name;
            if (RegOpenKeyExA(HKEY_CURRENT_USER, subKey.c_str(), 0, KEY_READ, &defaults) == ERROR_SUCCESS)
                break;
            defaults = nullptr;
        }
        const auto regDword = [&](const char* name, DWORD& value) {
            return ReadRegDword(key, name, value) ||
                   (defaults && ReadRegDword(defaults, name, value));
        };
        const auto regString = [&](const char* name, std::string& value) {
            return ReadRegString(key, name, value) ||
                   (defaults && ReadRegString(defaults, name, value));
        };

        if (!ReadRegString(key, "HostName", host) || host.empty()) {
            RegCloseKey(key);
            if (defaults)
                RegCloseKey(defaults);
            return false;
        }
        host = PuttyUrlDecode(host);

        hasPort = regDword("PortNumber", port);

        if (regString("UserName", userName))
            userName = PuttyUrlDecode(userName);

        // TryAgent is "authenticate with Pageant", on unless turned off;
        // AgentFwd only forwards the agent to the server.
        if (!regDword("TryAgent", useAgent))
            useAgent = 1;

        if (regString("PublicKeyFile", keyFile))
            keyFile = ExpandEnv(PuttyUrlDecode(keyFile));

        hasFsProto = regDword("FSProtocol", fsProtoRaw);

        // A non-zero `Tunnel` is an SSH session in front of the host, a
        // non-zero `ProxyMethod` a proxy.
        regDword("Tunnel", tunnel);
        regDword("ProxyMethod", proxyMethod);
        if (tunnel != 0) {
            regString("TunnelHostName", tunnelHost);
            regDword("TunnelPortNumber", tunnelPort);
            regString("TunnelUserName", tunnelUser);
            regString("TunnelPublicKeyFile", tunnelKey);
        }
        // A tunnel is dealt with below, together with any proxy beside it.
        if (dependency && tunnel == 0 && proxyMethod != 0) {
            std::string proxyHost, proxyUser;
            DWORD proxyPort = 0;
            regString("ProxyHost", proxyHost);
            regDword("ProxyPort", proxyPort);
            regString("ProxyUsername", proxyUser);
            proxyHost = PuttyUrlDecode(proxyHost);
            dependency->kind   = SessionDependency::Kind::Proxy;
            dependency->detail = proxyHost;
            DescribePuttyProxy(proxyMethod, proxyHost, proxyPort,
                               PuttyUrlDecode(proxyUser), *dependency);
        }
        RegCloseKey(key);
        if (defaults)
            RegCloseKey(defaults);
    } else {
        // Portable channel: sourceOrigin is the literal WinSCP.ini path.
        // Section name is `Sessions\<encoded>`.
        const std::string& ini = entry.sourceOrigin;
        std::string section;
        for (const auto& name : SubKeyNames(entry.displayName)) {
            section = std::string(kIniSessionsPrefix) + name;
            host = PuttyUrlDecode(ReadIniString(ini, section, "HostName"));
            if (!host.empty())
                break;
        }
        if (host.empty()) return false;
        const std::string sections[] = {
            section,
            std::string(kIniSessionsPrefix) + "Default%20Settings",
            std::string(kIniSessionsPrefix) + "Default Settings",
        };
        const auto iniString = [&](const char* name) {
            for (const auto& s : sections) {
                std::string v = ReadIniString(ini, s, name);
                if (!v.empty())
                    return v;
            }
            return std::string();
        };
        const auto iniDword = [&](const char* name) {
            for (const auto& s : sections) {
                const int v = ReadIniDword(ini, s, name);
                if (v >= 0)
                    return v;
            }
            return -1;
        };

        const int portRaw = iniDword("PortNumber");
        if (portRaw >= 0) { port = static_cast<DWORD>(portRaw); hasPort = true; }

        userName = PuttyUrlDecode(iniString("UserName"));

        const int agentRaw = iniDword("TryAgent");
        useAgent = agentRaw >= 0 ? static_cast<DWORD>(agentRaw) : 1;

        keyFile = ExpandEnv(PuttyUrlDecode(iniString("PublicKeyFile")));

        const int fsRaw = iniDword("FSProtocol");
        if (fsRaw >= 0) { fsProtoRaw = static_cast<DWORD>(fsRaw); hasFsProto = true; }

        if (iniDword("Tunnel") > 0) {
            tunnel     = 1;
            tunnelHost = iniString("TunnelHostName");
            tunnelUser = iniString("TunnelUserName");
            tunnelKey  = iniString("TunnelPublicKeyFile");
            const int tp = iniDword("TunnelPortNumber");
            if (tp > 0) tunnelPort = static_cast<DWORD>(tp);
        }
        const int method = iniDword("ProxyMethod");
        if (method > 0) proxyMethod = static_cast<DWORD>(method);

        if (dependency && tunnel == 0 && method > 0) {
            const std::string proxyHost = PuttyUrlDecode(iniString("ProxyHost"));
            const int proxyPort = iniDword("ProxyPort");
            dependency->kind   = SessionDependency::Kind::Proxy;
            dependency->detail = proxyHost;
            DescribePuttyProxy(static_cast<DWORD>(method), proxyHost,
                               proxyPort > 0 ? static_cast<DWORD>(proxyPort) : 0,
                               PuttyUrlDecode(iniString("ProxyUsername")),
                               *dependency);
        }
    }

    // Unsupported protocols (FTP/WebDAV/S3) fail LoadSettings so the
    // row silently disappears rather than showing an entry that will
    // never connect.
    const FsProtoResult proto =
        hasFsProto ? ClassifyFsProto(static_cast<int>(fsProtoRaw))
                   : FsProtoResult::UseSftp;
    if (proto == FsProtoResult::Unsupported)
        return false;

    out->server = ComposeServer(host, hasPort ? port : 0);
    out->user     = userName;
    out->useagent = (useAgent != 0);

    if (proto == FsProtoResult::UseScp) {
        // Pin the flags a minimal SCP server needs:
        //   scponly + scpfordata → force SCP transport, no SFTP subsystem probe
        //   unixlinebreaks=1     → skip shell-command probes for line-ending mode
        //   scpserver64bit=0     → skip the >2 GB shell-side capability probe
        out->scponly        = true;
        out->scpfordata     = true;
        out->unixlinebreaks = 1;
        out->scpserver64bit = 0;
    }

    if (!keyFile.empty())
        AssignImportedKeyFile(keyFile, out->privkeyfile, out->pubkeyfile);

    // The tunnel becomes the session's jump host. Its password stays behind
    // and is asked for on connect. Refused instead when there is no host to
    // go through, or when a proxy is set as well: the plugin's jump host
    // connects directly, so the proxy would be skipped.
    if (tunnel != 0) {
        tunnelHost = PuttyUrlDecode(tunnelHost);
        if (tunnelHost.empty() || proxyMethod != 0) {
            if (dependency) {
                dependency->kind   = SessionDependency::Kind::Tunnel;
                dependency->detail = tunnelHost;
            }
        } else {
            out->use_jump_host = true;
            out->jump_host     = tunnelHost;
            if (tunnelPort > 0 && tunnelPort <= 0xFFFF)
                out->jump_port = static_cast<unsigned short>(tunnelPort);
            out->jump_user = PuttyUrlDecode(tunnelUser);
            tunnelKey = ExpandEnv(PuttyUrlDecode(tunnelKey));
            if (!tunnelKey.empty())
                AssignImportedKeyFile(tunnelKey, out->jump_privkeyfile, out->jump_pubkeyfile);
        }
    }

    return true;
}

}  // namespace sftp
