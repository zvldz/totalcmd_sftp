#include "WinScpAdapter.h"
#include "SftpClient.h"
#include "global.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

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

// WinSCP uses PuTTY's URL-encoding scheme for spaces and other
// non-`A-Za-z0-9-_.` characters — same on-disk representation whether
// the session lives in the registry or in WinSCP.ini. Duplicate the
// codec here rather than pulling PuttyAdapter's copy sideways so the
// two adapters stay independently portable.
int HexToInt(char c) noexcept
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

std::string UrlDecode(const std::string& encoded)
{
    std::string out;
    out.reserve(encoded.size());
    for (size_t i = 0; i < encoded.size(); ++i) {
        const char ch = encoded[i];
        if (ch == '%' && i + 2 < encoded.size()) {
            const int hi = HexToInt(encoded[i + 1]);
            const int lo = HexToInt(encoded[i + 2]);
            if (hi >= 0 && lo >= 0) {
                out.push_back(static_cast<char>((hi << 4) | lo));
                i += 2;
                continue;
            }
        }
        out.push_back(ch);
    }
    return out;
}

// WinSCP encodes a much narrower unsafe set than PuTTY: session names
// like `root@192.168.88.127` or `test1/root@192.168.88.26` land in the
// registry verbatim (real observation), only characters that would
// actually break the registry path separator, break the on-disk INI
// key format, or be visually ambiguous get percent-encoded.
// Empirically confirmed set:
//   `\`  → registry subkey separator, must be encoded
//   ` `  → space, encoded as %20 (see `Default%20Settings` template)
//   `%`  → self-escape so round-trip through UrlDecode stays lossless
// Everything else passes through untouched — using the aggressive
// PuTTY-style set here would produce subkey names WinSCP never wrote.
std::string UrlEncode(const std::string& raw)
{
    std::string out;
    out.reserve(raw.size());
    for (unsigned char ch : raw) {
        const bool needsEscape = (ch == '\\' || ch == ' ' || ch == '%' || ch < 0x20);
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

bool ReadRegString(HKEY key, const char* valueName, std::string& out)
{
    DWORD type = 0;
    DWORD bytes = 0;
    LONG rc = RegQueryValueExA(key, valueName, nullptr, &type, nullptr, &bytes);
    if (rc != ERROR_SUCCESS ||
        (type != REG_SZ && type != REG_EXPAND_SZ) ||
        bytes == 0)
        return false;
    std::string buffer(bytes, '\0');
    rc = RegQueryValueExA(key, valueName, nullptr, &type,
                           reinterpret_cast<LPBYTE>(buffer.data()), &bytes);
    if (rc != ERROR_SUCCESS) return false;
    while (!buffer.empty() && buffer.back() == '\0')
        buffer.pop_back();
    out = std::move(buffer);
    return !out.empty();
}

bool ReadRegDword(HKEY key, const char* valueName, DWORD& out)
{
    DWORD type = 0;
    DWORD value = 0;
    DWORD bytes = sizeof(value);
    LONG rc = RegQueryValueExA(key, valueName, nullptr, &type,
                                reinterpret_cast<LPBYTE>(&value), &bytes);
    if (rc != ERROR_SUCCESS || type != REG_DWORD) return false;
    out = value;
    return true;
}

// GetPrivateProfileString wrapper that returns "" when the key is
// missing (Win32 default_value semantics), so callers can uniformly
// test for empty-string-means-absent without a separate probe.
std::string ReadIniString(const std::string& iniPath, const std::string& section,
                          const char* key)
{
    std::array<char, 4096> buf{};
    GetPrivateProfileStringA(section.c_str(), key, "",
        buf.data(), static_cast<DWORD>(buf.size() - 1),
        iniPath.c_str());
    return std::string(buf.data());
}

// GetPrivateProfileInt with default -1 so callers can distinguish
// "value absent" from "value present and zero".
int ReadIniDword(const std::string& iniPath, const std::string& section,
                  const char* key)
{
    return GetPrivateProfileIntA(section.c_str(), key, -1, iniPath.c_str());
}

std::string ExpandEnv(const std::string& raw)
{
    std::string expanded(MAX_PATH, '\0');
    DWORD len = ExpandEnvironmentStringsA(raw.c_str(), expanded.data(),
                                           static_cast<DWORD>(expanded.size()));
    if (len == 0 || len > expanded.size())
        return raw;
    expanded.resize(len - 1);
    return expanded;
}

bool EndsWithI(const std::string& s, const char* suffix) noexcept
{
    const size_t slen = std::strlen(suffix);
    if (s.size() < slen) return false;
    return _stricmp(s.c_str() + s.size() - slen, suffix) == 0;
}

// WinSCP FSProtocol registry value classification.
//
// Actual mapping from WinSCP's own enum TFSProtocol (source/core/
// SessionData.h in the WinSCP tree):
//
//   0 = fsSCPonly    — SCP transport, no SFTP fallback
//   1 = fsSFTP       — SFTP with SCP fallback if server rejects the subsystem
//   2 = fsSFTPonly   — SFTP transport only
//   5 = fsFTP        — plain FTP or FTPS (not supported by this plugin)
//   6 = fsWebDAV     — not supported
//   7 = fsS3         — not supported
//
// Wesmar's legacy F11 import used to read this as { 0 = SFTP, 1 = SCP,
// else = unsupported } — that was wrong on every value (0 was SCP not
// SFTP, 1 was SFTP not SCP, 2 was SFTP-only being rejected as
// unsupported). This adapter uses the real mapping. Absent value is
// treated as SFTP because that is WinSCP's default when the user
// picked "SFTP" in the New Site dialog and never touched the advanced
// options.
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

// Assign an already-populated key-file path (URL-decoded, env-expanded)
// into the right slot of tConnectSettings. Matches the same
// extension-based rules the PuTTY adapter and wesmar's legacy code use.
void AssignKeyFile(pConnectSettings out, const std::string& keyFile)
{
    if (EndsWithI(keyFile, ".ppk") || EndsWithI(keyFile, ".pem"))
        out->privkeyfile = keyFile;
    else if (EndsWithI(keyFile, ".pub"))
        out->pubkeyfile = keyFile;
    // Unknown extensions dropped rather than guessed at.
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

EnumerationResult WinScpAdapter::EnumerateStandard()
{
    EnumerationResult r;

    HKEY root = nullptr;
    LONG rc = RegOpenKeyExA(HKEY_CURRENT_USER, kWinScpSessionsRoot,
                             0, KEY_READ, &root);
    SFTP_LOG("WINSCP", "EnumerateStandard: RegOpenKeyExA rc=%ld", rc);
    if (rc != ERROR_SUCCESS) {
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
        SFTP_LOG("WINSCP", "  RegEnumKeyExA index=%lu rc=%ld nameLen=%lu name='%s'",
                 index, rc, nameLen, rc == ERROR_SUCCESS ? nameBuf.data() : "");
        if (rc == ERROR_NO_MORE_ITEMS) break;
        ++index;
        if (rc != ERROR_SUCCESS) continue;

        // WinSCP writes a "Default%20Settings" template row that holds
        // fallback values — never a real session. Same filter the
        // PuTTY adapter and wesmar's legacy code apply.
        if (_stricmp(nameBuf.data(), "Default%20Settings") == 0) { ++filtered; continue; }

        ExternalSessionEntry e;
        e.displayName  = UrlDecode(std::string(nameBuf.data(), nameLen));
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
    const DWORD attrs = GetFileAttributesA(path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        r.status = EnumerationStatus::Unreachable;
        return r;
    }

    // Enumerate every section name in the INI, keep only those matching
    // "Sessions\<name>". GetPrivateProfileSectionNames returns a
    // double-NUL-terminated block; ~64 KB is enough for a portable
    // config with hundreds of sessions.
    std::array<char, 65536> sectBuf{};
    const DWORD gotLen = GetPrivateProfileSectionNamesA(
        sectBuf.data(),
        static_cast<DWORD>(sectBuf.size() - 1),
        path.c_str());
    if (gotLen == 0) {
        r.status = EnumerationStatus::OkEmpty;
        return r;
    }

    const size_t prefixLen = std::strlen(kIniSessionsPrefix);
    const char* p = sectBuf.data();
    while (*p) {
        const std::string section(p);
        p += section.size() + 1;

        if (section.size() <= prefixLen) continue;
        if (_strnicmp(section.c_str(), kIniSessionsPrefix, prefixLen) != 0)
            continue;

        const std::string keyName = section.substr(prefixLen);
        if (keyName.empty()) continue;
        if (_stricmp(keyName.c_str(), "Default Settings") == 0 ||
            _stricmp(keyName.c_str(), "Default%20Settings") == 0)
            continue;

        ExternalSessionEntry e;
        e.displayName  = UrlDecode(keyName);
        e.sourceOrigin = path;   // literal file path — see LoadSettings
        r.sessions.push_back(std::move(e));
    }

    r.status = r.sessions.empty()
        ? EnumerationStatus::OkEmpty
        : EnumerationStatus::OkWithSessions;
    return r;
}

bool WinScpAdapter::LoadSettings(const ExternalSessionEntry& entry,
                                  pConnectSettings out)
{
    if (!out) return false;

    const std::string subKeyName = UrlEncode(entry.displayName);
    SFTP_LOG("WINSCP", "LoadSettings: display='%s' encoded='%s' origin='%s'",
             entry.displayName.c_str(), subKeyName.c_str(),
             entry.sourceOrigin.c_str());

    // Populated below from whichever channel this entry came from.
    std::string host, userName, keyFile;
    DWORD port = 0, useAgent = 0, fsProtoRaw = 0;
    bool  hasPort = false, hasFsProto = false;

    if (entry.sourceOrigin == "standard") {
        const std::string subKey =
            std::string(kWinScpSessionsRoot) + "\\" + subKeyName;
        HKEY key = nullptr;
        LONG rc = RegOpenKeyExA(HKEY_CURRENT_USER, subKey.c_str(),
                                 0, KEY_READ, &key);
        SFTP_LOG("WINSCP", "  RegOpenKeyExA subKey='%s' rc=%ld",
                 subKey.c_str(), rc);
        if (rc != ERROR_SUCCESS) return false;

        const bool hostOk = ReadRegString(key, "HostName", host);
        SFTP_LOG("WINSCP", "  HostName ok=%d value='%s'",
                 hostOk, host.c_str());
        if (!hostOk || host.empty()) {
            RegCloseKey(key);
            return false;
        }
        host = UrlDecode(host);

        hasPort = ReadRegDword(key, "PortNumber", port);

        if (ReadRegString(key, "UserName", userName))
            userName = UrlDecode(userName);

        if (!ReadRegDword(key, "AgentFwd", useAgent))
            ReadRegDword(key, "AuthAgent", useAgent);

        if (ReadRegString(key, "PublicKeyFile", keyFile))
            keyFile = ExpandEnv(UrlDecode(keyFile));

        hasFsProto = ReadRegDword(key, "FSProtocol", fsProtoRaw);
        RegCloseKey(key);
    } else {
        // Portable channel: sourceOrigin is the literal WinSCP.ini path.
        // Section name is `Sessions\<encoded>`.
        const std::string section = std::string(kIniSessionsPrefix) + subKeyName;
        host = UrlDecode(ReadIniString(entry.sourceOrigin, section, "HostName"));
        if (host.empty()) return false;

        const int portRaw = ReadIniDword(entry.sourceOrigin, section, "PortNumber");
        if (portRaw >= 0) { port = static_cast<DWORD>(portRaw); hasPort = true; }

        userName = UrlDecode(ReadIniString(entry.sourceOrigin, section, "UserName"));

        const int agentRaw = ReadIniDword(entry.sourceOrigin, section, "AgentFwd");
        if (agentRaw >= 0) useAgent = static_cast<DWORD>(agentRaw);
        else {
            const int auth2 = ReadIniDword(entry.sourceOrigin, section, "AuthAgent");
            if (auth2 >= 0) useAgent = static_cast<DWORD>(auth2);
        }

        keyFile = ExpandEnv(UrlDecode(ReadIniString(entry.sourceOrigin, section, "PublicKeyFile")));

        const int fsRaw = ReadIniDword(entry.sourceOrigin, section, "FSProtocol");
        if (fsRaw >= 0) { fsProtoRaw = static_cast<DWORD>(fsRaw); hasFsProto = true; }
    }

    // Classify the transport. Unsupported protocols (FTP/WebDAV/S3)
    // cause the whole LoadSettings call to fail so the row silently
    // disappears from the source folder instead of showing an entry
    // that will never connect. Matches wesmar's legacy F11 handling.
    const FsProtoResult proto =
        hasFsProto ? ClassifyFsProto(static_cast<int>(fsProtoRaw))
                   : FsProtoResult::UseSftp;
    SFTP_LOG("WINSCP", "  fsProto hasFsProto=%d raw=%lu classified=%d",
             hasFsProto ? 1 : 0, fsProtoRaw, static_cast<int>(proto));
    if (proto == FsProtoResult::Unsupported)
        return false;

    if (hasPort && port > 0 && port != 22) {
        char portBuf[16];
        std::snprintf(portBuf, sizeof(portBuf), ":%lu",
                      static_cast<unsigned long>(port));
        out->server = host + portBuf;
    } else {
        out->server = host;
    }
    out->user     = userName;
    out->useagent = (useAgent != 0);

    if (proto == FsProtoResult::UseScp) {
        // WinSCP session configured as SCP — matches the legacy import's
        // flag set: scponly + scpfordata force the SCP transport,
        // unixlinebreaks=1 skips auto-detection probes that would try to
        // execute shell commands and confuse a minimal SCP server, and
        // scpserver64bit=0 (written to INI as `largefilesupport=0`) turns
        // off the >2GB shell probe legacy wesmar also disabled for
        // WinSCP-as-SCP sessions.
        out->scponly        = true;
        out->scpfordata     = true;
        out->unixlinebreaks = 1;
        out->scpserver64bit = 0;
    }

    if (!keyFile.empty())
        AssignKeyFile(out, keyFile);

    return true;
}

}  // namespace sftp
