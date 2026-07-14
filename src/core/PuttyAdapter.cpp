#include "PuttyAdapter.h"
#include "SftpClient.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <array>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace sftp {

namespace {

// The registry root every PuTTY-compatible tool writes into.
// Software\SimonTatham\PuTTY\Sessions under HKEY_CURRENT_USER.
constexpr const char* kPuttySessionsRoot = "Software\\SimonTatham\\PuTTY\\Sessions";

// PuTTY escapes session name characters outside a small allowed set
// using RFC 1738 style %XX hex, so the on-disk registry key name is
// URL-encoded and the human-friendly form we want to show the user
// requires decoding. LoadSettings then re-encodes to reopen the key.
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

// PuTTY's own encode routine: unreserved ASCII stays, everything else
// becomes %XX. Matches winstore.c:mungestr() in the PuTTY sources.
std::string UrlEncode(const std::string& raw)
{
    std::string out;
    out.reserve(raw.size());
    for (unsigned char ch : raw) {
        const bool safe =
            (ch >= 'A' && ch <= 'Z') ||
            (ch >= 'a' && ch <= 'z') ||
            (ch >= '0' && ch <= '9') ||
            ch == '-' || ch == '_' || ch == '.';
        if (safe) {
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
    // Strip the NUL RegQueryValueExA reports in `bytes`.
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
    if (rc != ERROR_SUCCESS || type != REG_DWORD)
        return false;
    out = value;
    return true;
}

// Expand any %ENV% references in a Windows path string. PuTTY sessions
// commonly reference key files via %USERPROFILE%\...\id_rsa; we resolve
// the substitution before writing the path into our INI so the plugin's
// SFTP auth stage can use it verbatim.
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

// Load a `.reg` file into a UTF-8 std::string. `.reg` files come in
// three encodings — PortableApps PuTTY writes UTF-16 LE with BOM, older
// exports use ANSI ("REGEDIT4" header) or UTF-8. Detect from BOM, fall
// back to CP_ACP for the raw case; caller then parses lines.
bool ReadRegFileAsUtf8(const std::string& path, std::string& outUtf8)
{
    HANDLE h = CreateFileA(path.c_str(), GENERIC_READ,
                            FILE_SHARE_READ, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER sz{};
    GetFileSizeEx(h, &sz);
    if (sz.QuadPart <= 0 || sz.QuadPart > 100 * 1024 * 1024) {
        // Reject empty and > 100 MB — Regedit exports of a single PuTTY
        // Sessions branch are typically tens of KB; anything larger is
        // either a mistake or someone trying to feed us a full
        // NTUSER.DAT-sized dump.
        CloseHandle(h);
        return false;
    }

    std::vector<uint8_t> raw(static_cast<size_t>(sz.QuadPart));
    DWORD readBytes = 0;
    const BOOL ok = ReadFile(h, raw.data(),
                              static_cast<DWORD>(raw.size()),
                              &readBytes, nullptr);
    CloseHandle(h);
    if (!ok || readBytes == 0) return false;
    raw.resize(readBytes);

    // BOM detection.
    if (raw.size() >= 2 && raw[0] == 0xFF && raw[1] == 0xFE) {
        // UTF-16 LE.
        const wchar_t* wide = reinterpret_cast<const wchar_t*>(raw.data() + 2);
        const int wideCount = static_cast<int>((raw.size() - 2) / sizeof(wchar_t));
        const int need = WideCharToMultiByte(CP_UTF8, 0, wide, wideCount,
                                              nullptr, 0, nullptr, nullptr);
        if (need <= 0) return false;
        outUtf8.assign(static_cast<size_t>(need), '\0');
        WideCharToMultiByte(CP_UTF8, 0, wide, wideCount,
                             outUtf8.data(), need, nullptr, nullptr);
        return true;
    }
    if (raw.size() >= 3 && raw[0] == 0xEF && raw[1] == 0xBB && raw[2] == 0xBF) {
        // UTF-8 with BOM — strip and hand back as-is.
        outUtf8.assign(reinterpret_cast<const char*>(raw.data() + 3),
                        raw.size() - 3);
        return true;
    }
    // No BOM — treat as CP_ACP (ANSI), the "REGEDIT4" era default.
    const int need = MultiByteToWideChar(CP_ACP, 0,
        reinterpret_cast<const char*>(raw.data()),
        static_cast<int>(raw.size()), nullptr, 0);
    if (need <= 0) {
        // Fall back to raw bytes; parser only needs ASCII-safe control
        // characters (`[`, `]`, `"`, `=`, digits, letters).
        outUtf8.assign(reinterpret_cast<const char*>(raw.data()), raw.size());
        return true;
    }
    std::wstring wide(static_cast<size_t>(need), L'\0');
    MultiByteToWideChar(CP_ACP, 0,
        reinterpret_cast<const char*>(raw.data()),
        static_cast<int>(raw.size()), wide.data(), need);
    const int u8Need = WideCharToMultiByte(CP_UTF8, 0,
        wide.data(), need, nullptr, 0, nullptr, nullptr);
    outUtf8.assign(static_cast<size_t>(u8Need), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.data(), need,
                        outUtf8.data(), u8Need, nullptr, nullptr);
    return true;
}

// Un-escape a Regedit-quoted string value: `\\` → `\`, `\"` → `"`, drop
// surrounding quotes. Anything else stays literal. `input` is the raw
// content between the two `"` delimiters (inclusive is fine — we strip
// them here).
std::string UnescapeRegString(std::string_view input)
{
    if (input.size() >= 2 && input.front() == '"' && input.back() == '"')
        input = input.substr(1, input.size() - 2);
    std::string out;
    out.reserve(input.size());
    for (size_t i = 0; i < input.size(); ++i) {
        if (input[i] == '\\' && i + 1 < input.size()) {
            char nxt = input[i + 1];
            if (nxt == '\\' || nxt == '"') { out.push_back(nxt); ++i; continue; }
        }
        out.push_back(input[i]);
    }
    return out;
}

// Everything we care about in a parsed `.reg` file: which Sessions\<name>
// subkeys exist, and the field values inside each. Callers pull sessions
// through `sessions` (URL-encoded key names, ready to be UrlDecode'd for
// display), and look each up in `values` by "<sessionKey>::<valueName>".
struct RegFileParsed {
    std::vector<std::string>                       sessions;   // URL-encoded names
    std::unordered_map<std::string, std::string>   strings;    // "<sess>::<name>" → REG_SZ
    std::unordered_map<std::string, uint32_t>      dwords;     // "<sess>::<name>" → REG_DWORD
};

// Parse a `.reg` file's text form (already converted to UTF-8 by
// ReadRegFileAsUtf8). Only interested in Sessions\<name> subkeys — every
// other branch (Jumplist, SshHostKeys, the empty Sessions\ header, etc.)
// is skipped. Value types other than REG_SZ / REG_DWORD are silently
// ignored — PuTTY session fields we care about are all in those two.
void ParseRegFile(const std::string& utf8, RegFileParsed& out)
{
    static const std::string kSessionsPrefix =
        "HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\";

    std::string currentSession;  // empty when the current section is not a session

    auto flushLine = [&](std::string_view line) {
        // Trim CR (line endings from CRLF files).
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n' ||
                                  line.back() == ' ' || line.back() == '\t'))
            line.remove_suffix(1);
        if (line.empty()) return;

        // Section header?
        if (line.front() == '[' && line.back() == ']') {
            std::string_view inner = line.substr(1, line.size() - 2);
            if (inner.size() > kSessionsPrefix.size() &&
                _strnicmp(inner.data(), kSessionsPrefix.data(),
                          kSessionsPrefix.size()) == 0)
            {
                std::string sess(inner.substr(kSessionsPrefix.size()));
                // Guard against nested subkeys under a session (rare;
                // PuTTY does not create any today). Reject anything with
                // a backslash inside — we only track leaf sessions.
                if (sess.find('\\') == std::string::npos && !sess.empty()) {
                    currentSession = std::move(sess);
                    out.sessions.push_back(currentSession);
                    return;
                }
            }
            currentSession.clear();
            return;
        }

        if (currentSession.empty()) return;

        // Value line: `"Name"=...`
        if (line.size() < 4 || line.front() != '"') return;
        const size_t nameEnd = line.find('"', 1);
        if (nameEnd == std::string_view::npos) return;
        const std::string name(line.substr(1, nameEnd - 1));
        const size_t eq = line.find('=', nameEnd);
        if (eq == std::string_view::npos) return;
        std::string_view rhs = line.substr(eq + 1);
        // REG_SZ: `"value"` (may contain escaped \" or \\; multi-line
        // string values are legal but PuTTY never writes them so we do
        // not try to reassemble continuation lines).
        if (!rhs.empty() && rhs.front() == '"') {
            const std::string key = currentSession + "::" + name;
            out.strings[key] = UnescapeRegString(rhs);
            return;
        }
        // REG_DWORD: `dword:XXXXXXXX` (8 hex digits, big-endian text but
        // logically a plain little-endian u32 on the wire).
        static const char kDwordPrefix[] = "dword:";
        if (rhs.size() >= sizeof(kDwordPrefix) - 1 &&
            _strnicmp(rhs.data(), kDwordPrefix, sizeof(kDwordPrefix) - 1) == 0)
        {
            std::string_view hex = rhs.substr(sizeof(kDwordPrefix) - 1);
            uint32_t v = 0;
            for (char c : hex) {
                if (c >= '0' && c <= '9') v = (v << 4) | uint32_t(c - '0');
                else if (c >= 'a' && c <= 'f') v = (v << 4) | uint32_t(10 + c - 'a');
                else if (c >= 'A' && c <= 'F') v = (v << 4) | uint32_t(10 + c - 'A');
                else break;
            }
            out.dwords[currentSession + "::" + name] = v;
        }
        // Everything else (hex(...):, hex(7):, "..." continued lines) is
        // ignored — none of the fields we consume are stored that way.
    };

    // Split into lines and hand each to flushLine. Handles both CRLF and
    // LF-only files.
    size_t start = 0;
    for (size_t i = 0; i <= utf8.size(); ++i) {
        if (i == utf8.size() || utf8[i] == '\n') {
            flushLine(std::string_view(utf8.data() + start, i - start));
            start = i + 1;
        }
    }
}

}  // namespace

bool PuttyAdapter::DetectStandard() const noexcept
{
    HKEY key = nullptr;
    LONG rc = RegOpenKeyExA(HKEY_CURRENT_USER, kPuttySessionsRoot,
                             0, KEY_READ, &key);
    if (rc != ERROR_SUCCESS) return false;
    RegCloseKey(key);
    return true;
}

EnumerationResult PuttyAdapter::EnumerateStandard()
{
    EnumerationResult r;

    HKEY root = nullptr;
    LONG rc = RegOpenKeyExA(HKEY_CURRENT_USER, kPuttySessionsRoot,
                             0, KEY_READ, &root);
    if (rc != ERROR_SUCCESS) {
        r.status = EnumerationStatus::Unreachable;
        return r;
    }

    DWORD index = 0;
    for (;;) {
        std::array<char, 512> nameBuf{};
        DWORD nameLen = static_cast<DWORD>(nameBuf.size());
        rc = RegEnumKeyExA(root, index, nameBuf.data(), &nameLen,
                            nullptr, nullptr, nullptr, nullptr);
        if (rc == ERROR_NO_MORE_ITEMS)
            break;
        ++index;
        if (rc != ERROR_SUCCESS)
            continue;

        // The wesmar-import path filters "Default%20Settings" — PuTTY's
        // template row that carries fallback field values, never a real
        // session. Same treatment here so it does not surface as an
        // openable session in the panel.
        if (_stricmp(nameBuf.data(), "Default%20Settings") == 0)
            continue;

        ExternalSessionEntry e;
        e.displayName  = UrlDecode(std::string(nameBuf.data(), nameLen));
        e.sourceOrigin = "standard";
        r.sessions.push_back(std::move(e));
    }
    RegCloseKey(root);

    r.status = r.sessions.empty()
        ? EnumerationStatus::OkEmpty
        : EnumerationStatus::OkWithSessions;
    return r;
}

EnumerationResult PuttyAdapter::EnumerateCustomPath(const std::string& path)
{
    EnumerationResult r;

    std::string text;
    if (!ReadRegFileAsUtf8(path, text)) {
        // File missing or unreadable — treat as Unreachable so the
        // channel's cached entries survive per the standard prune rules.
        r.status = EnumerationStatus::Unreachable;
        return r;
    }

    RegFileParsed parsed;
    ParseRegFile(text, parsed);

    for (const auto& sessKeyName : parsed.sessions) {
        // Same skip as EnumerateStandard — PuTTY's "Default Settings"
        // template row is never a real session.
        if (_stricmp(sessKeyName.c_str(), "Default%20Settings") == 0)
            continue;

        ExternalSessionEntry e;
        e.displayName  = UrlDecode(sessKeyName);
        e.sourceOrigin = path;   // literal file path — see LoadSettings
        r.sessions.push_back(std::move(e));
    }

    r.status = r.sessions.empty()
        ? EnumerationStatus::OkEmpty
        : EnumerationStatus::OkWithSessions;
    return r;
}

bool PuttyAdapter::LoadSettings(const ExternalSessionEntry& entry,
                                 pConnectSettings out)
{
    if (!out) return false;

    // Round-trip the displayName back through URL encoding to hit the
    // exact subkey PuTTY stored it under — the same encoding scheme is
    // used both in the registry and in .reg export files.
    const std::string subKeyName = UrlEncode(entry.displayName);

    // Field values, populated from whichever channel this entry came
    // from. Empty string / zero here means "field not present".
    std::string host, userName, keyFile, lineCodePage;
    DWORD       port = 0, useAgent = 0;
    bool        hasPort = false;

    if (entry.sourceOrigin == "standard") {
        // Standard channel: fields live under
        // HKCU\Software\SimonTatham\PuTTY\Sessions\<encoded name>.
        const std::string subKey =
            std::string(kPuttySessionsRoot) + "\\" + subKeyName;
        HKEY key = nullptr;
        LONG rc = RegOpenKeyExA(HKEY_CURRENT_USER, subKey.c_str(),
                                 0, KEY_READ, &key);
        if (rc != ERROR_SUCCESS) return false;

        if (!ReadRegString(key, "HostName", host) || host.empty()) {
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

        ReadRegString(key, "LineCodePage", lineCodePage);
        RegCloseKey(key);
    } else {
        // Custom channel: entry.sourceOrigin is the literal path to a
        // `putty.reg` export file. Re-parse the whole file (small,
        // rarely called — user F5-refresh + first enter per session),
        // then pull the fields for this specific session from the
        // parsed map.
        std::string text;
        if (!ReadRegFileAsUtf8(entry.sourceOrigin, text))
            return false;
        RegFileParsed parsed;
        ParseRegFile(text, parsed);

        const std::string prefix = subKeyName + "::";
        auto pickString = [&](const char* name, std::string& out_) {
            auto it = parsed.strings.find(prefix + name);
            if (it != parsed.strings.end())
                out_ = it->second;
        };
        auto pickDword = [&](const char* name, DWORD& out_, bool& hasIt) {
            auto it = parsed.dwords.find(prefix + name);
            if (it != parsed.dwords.end()) {
                out_ = it->second;
                hasIt = true;
            }
        };

        pickString("HostName", host);
        host = UrlDecode(host);
        if (host.empty()) return false;

        pickDword("PortNumber", port, hasPort);

        pickString("UserName", userName);
        userName = UrlDecode(userName);

        bool hadAgent = false;
        pickDword("AgentFwd", useAgent, hadAgent);
        if (!hadAgent)
            pickDword("AuthAgent", useAgent, hadAgent);

        pickString("PublicKeyFile", keyFile);
        keyFile = ExpandEnv(UrlDecode(keyFile));

        pickString("LineCodePage", lineCodePage);
    }

    // Compose the connect fields the cache writer will persist. The
    // sentinel-based policy in ImportCache::WriteSessionSection means
    // fields we leave at their default (empty string, false, -1) never
    // reach the cache — no need to zero anything out explicitly.
    if (hasPort && port > 0 && port != 22) {
        char portBuf[16];
        std::snprintf(portBuf, sizeof(portBuf), ":%lu",
                      static_cast<unsigned long>(port));
        out->server = host + portBuf;
    } else {
        out->server = host;
    }
    out->user = userName;
    out->useagent = (useAgent != 0);

    if (!keyFile.empty()) {
        // PuTTY calls it "PublicKeyFile" but always stores the *private*
        // key path; the .pub companion is a separate concept. Match the
        // wesmar import heuristic: .ppk / .pem → privkeyfile,
        // .pub → pubkeyfile. Unknown extensions get dropped rather than
        // guessed at. PpkConverter handles the .ppk → OpenSSH temp-file
        // conversion downstream in SftpAuth.
        if (EndsWithI(keyFile, ".ppk") || EndsWithI(keyFile, ".pem"))
            out->privkeyfile = keyFile;
        else if (EndsWithI(keyFile, ".pub"))
            out->pubkeyfile = keyFile;
    }

    if (_stricmp(lineCodePage.c_str(), "UTF-8") == 0)
        out->utf8names = 1;

    return true;
}

}  // namespace sftp
