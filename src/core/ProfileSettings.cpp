#include "global.h"
#include <windows.h>
#include <algorithm>
#include <array>
#include <vector>
#include <format>
#include <sstream>
#include <string_view>
#include "SftpClient.h"
#include "SftpInternal.h"
#include "ConnectionDialog.h"
#include "IniFile.h"
#include "ProfileSettings.h"

// Which proxy records exist, in order. Numbering may have holes: deleting a
// record leaves the ones above it where they are, so that a number stays a
// stable identity for the sessions and imports that point at it. Counting up
// until a number is missing would stop at the first hole, so the sections
// themselves are what gets read. Record one is `[proxy]`, the rest `[proxyN]`.
std::vector<int> EnumerateProxyNumbers(LPCSTR iniFileName)
{
    std::vector<int> numbers;
    // All of them: a list cut short would hide records, and a new one would
    // then be given the number of one that exists.
    for (const std::string& section : IniSectionNameList(iniFileName)) {
        const char* p = section.c_str();
        if (_strnicmp(p, "proxy", 5) != 0)
            continue;
        const char* tail = p + 5;
        if (!*tail) {
            numbers.push_back(1);
            continue;
        }
        // Only digits follow the prefix in a record name; `proxyjump` and the
        // like are other people's sections.
        int n = 0;
        for (const char* d = tail; *d; ++d) {
            if (*d < '0' || *d > '9') { n = 0; break; }
            n = n * 10 + (*d - '0');
        }
        if (n > 1)
            numbers.push_back(n);
    }
    std::sort(numbers.begin(), numbers.end());
    return numbers;
}

// The number a new proxy record may take. It has to clear two things, not one:
// every record that exists, and every number a session still points at. Stale
// references outlive their record — a session keeps `proxynr=1` long after
// `[proxy]` is gone — and handing that number to a new record would quietly
// route those sessions through it.
int NextFreeProxyNr(LPCSTR iniFileName)
{
    const std::vector<int> existing = EnumerateProxyNumbers(iniFileName);
    int highest = existing.empty() ? 0 : existing.back();

    std::array<char, wdirtypemax> name{};
    SERVERHANDLE hdl = FindFirstServer(name.data(), name.size() - 1);
    while (hdl) {
        const int referenced = static_cast<int>(IniGetInt(name.data(), "proxynr", 0, iniFileName));
        if (referenced > highest)
            highest = referenced;
        hdl = FindNextServer(hdl, name.data(), name.size() - 1);
    }
    return highest + 1;
}

// The record that already describes this proxy, or 0 when none does. Identity
// is the route: kind, server and user name. The password takes no part —
// passwords do not travel between machines, so two records that differ only in
// whether one is stored describe the same proxy.
int FindMatchingProxyNr(int proxytype, const std::string& server,
                        const std::string& user, LPCSTR iniFileName)
{
    for (const int proxynr : EnumerateProxyNumbers(iniFileName)) {
        tConnectSettings data;
        if (!LoadProxySettingsFromNr(proxynr, &data, iniFileName))
            continue;
        if (static_cast<int>(data.proxytype) == proxytype &&
            _stricmp(data.proxyserver.c_str(), server.c_str()) == 0 &&
            _stricmp(data.proxyuser.c_str(), user.c_str()) == 0)
        {
            return proxynr;
        }
    }
    return 0;
}

// A password as `section` keeps it under `key`, decrypted. The buffers take
// what the writers allow (an encrypted value of up to 1024 characters), so a
// long password is not lost to a short buffer; both are wiped.
static std::string LoadPasswordSetting(LPCSTR section, LPCSTR key, LPCSTR iniFileName)
{
    std::array<char, 2048> stored{};
    std::string out;
    if (IniGetString(section, key, "", stored.data(), static_cast<DWORD>(stored.size() - 1), iniFileName)) {
        std::array<char, 1024> plain{};
        DecryptString(stored.data(), plain.data(), static_cast<UINT>(plain.size()));
        out = plain.data();
        SecureZeroMemory(plain.data(), plain.size());
    }
    SecureZeroMemory(stored.data(), stored.size());
    return out;
}

// A file or folder mode: octal digits only, up to 07777; anything else
// gives `fallback` rather than a mode of 0, which would lock the user out
// of what is created.
static int ParseModeSetting(const char* text, int fallback)
{
    const size_t len = strlen(text);
    if (len == 0 || len > 5 || strspn(text, "01234567") != len)
        return fallback;
    const long mode = strtol(text, nullptr, 8);
    return mode > 0 && mode <= 07777 ? static_cast<int>(mode) : fallback;
}

bool LoadProxySettingsFromNr(int proxynr, pConnectSettings ConnectResults, LPCSTR iniFileName)
{
    if (proxynr > 0) {
        const std::string proxyentry = proxynr > 1 ? std::format("proxy{}", proxynr) : "proxy";
        ConnectResults->proxytype = sftp::Proxy::notused;
        int type = IniGetInt(proxyentry.data(), "proxytype", -1, iniFileName);
        if (type >= 0)
            ConnectResults->proxytype = (sftp::Proxy)type;
        ConnectResults->proxyserver = IniGetValue(proxyentry.data(), "proxyserver", iniFileName);
        ConnectResults->proxyuser = IniGetValue(proxyentry.data(), "proxyuser", iniFileName);
        ConnectResults->proxypassword = LoadPasswordSetting(proxyentry.data(), "proxypassword", iniFileName);
        return (type != -1 || proxynr == 1);
    } else {
        ConnectResults->proxytype = sftp::Proxy::notused;
        ConnectResults->proxyserver.clear();
        ConnectResults->proxyuser.clear();
        ConnectResults->proxypassword.clear();
        return false;
    }
}

bool LoadServerSettings(LPCSTR DisplayName, pConnectSettings ConnectResults, LPCSTR iniFileName)
{
    std::array<char, 6> modbuf{};
    ConnectResults->DisplayName = DisplayName ? DisplayName : "";
    ConnectResults->IniFileName = iniFileName ? iniFileName : "";
    ConnectResults->server = IniGetValue(DisplayName, "server", iniFileName);
    ConnectResults->protocoltype=IniGetInt(DisplayName, "protocol", 0, iniFileName);
    ConnectResults->transfermode = IniGetInt(DisplayName, "transfermode", 0, iniFileName);
    if (ConnectResults->transfermode < 0 || ConnectResults->transfermode > 3)
        ConnectResults->transfermode = 0;
    // UTF-8 values, read whole: a fixed buffer would cut a long key path
    // that the dialog saved complete.
    ConnectResults->user = IniGetValue(DisplayName, "user", iniFileName);
    ConnectResults->savedfingerprint = IniGetValue(DisplayName, "fingerprint", iniFileName);
    ConnectResults->pubkeyfile = IniGetValue(DisplayName, "pubkeyfile", iniFileName);
    ConnectResults->privkeyfile = IniGetValue(DisplayName, "privkeyfile", iniFileName);
    ConnectResults->useagent = IniGetInt(DisplayName, "useagent", 0, iniFileName) != 0;

    IniGetString(DisplayName, "filemod", "644", modbuf.data(), modbuf.size() - 1, iniFileName);
    ConnectResults->filemod = ParseModeSetting(modbuf.data(), 0644);
    IniGetString(DisplayName, "dirmod", "755", modbuf.data(), modbuf.size() - 1, iniFileName);
    ConnectResults->dirmod = ParseModeSetting(modbuf.data(), 0755);

    ConnectResults->compressed = IniGetInt(DisplayName, "compression", 0, iniFileName) != 0;
    ConnectResults->scpfordata = IniGetInt(DisplayName, "scpfordata", 0, iniFileName) != 0;
    ConnectResults->scponly = IniGetInt(DisplayName, "scponly", 0, iniFileName) != 0;
    if (ConnectResults->scponly)
        ConnectResults->scpfordata = true;
    ConnectResults->shell_transfer_dd = IniGetInt(DisplayName, "shelltransfer", 0, iniFileName) != 0;
    ConnectResults->shell_transfer_force =
        IniGetInt(DisplayName, "shelltransferforce",
                  ConnectResults->shell_transfer_dd ? 1 : 0,
                  iniFileName) != 0;
    ConnectResults->shell_dd_b64only  = false;
    ConnectResults->loginNoiseHandling = IniGetInt(DisplayName, "loginnoise", 1, iniFileName) != 0;
    ConnectResults->php_http_mode = IniGetInt(DisplayName, "phphttpmode", 0, iniFileName);
    if (ConnectResults->php_http_mode < 0 || ConnectResults->php_http_mode > 2)
        ConnectResults->php_http_mode = 0;
    ConnectResults->php_chunk_mib = IniGetInt(DisplayName, "phpchunkmb", 0, iniFileName);
    if (!(ConnectResults->php_chunk_mib == 0 || ConnectResults->php_chunk_mib == 1 ||
          ConnectResults->php_chunk_mib == 2 || ConnectResults->php_chunk_mib == 4 ||
          ConnectResults->php_chunk_mib == 8 || ConnectResults->php_chunk_mib == 16 ||
          ConnectResults->php_chunk_mib == 32 || ConnectResults->php_chunk_mib == 64))
        ConnectResults->php_chunk_mib = 0;
    ConnectResults->php_recommended_chunk_mib = 0;
    ConnectResults->php_tar = IniGetInt(DisplayName, "phptar", 0, iniFileName) != 0;
    ConnectResults->lan_pair_role = IniGetInt(DisplayName, "lanpairrole", 0, iniFileName);
    if (ConnectResults->lan_pair_role < 0 || ConnectResults->lan_pair_role > 2)
        ConnectResults->lan_pair_role = 0;
    ConnectResults->lan_pair_peer = IniGetValue(DisplayName, "lanpairpeer", iniFileName);
    ConnectResults->lan_pair_timeout_min = IniGetInt(DisplayName, "lanpairtimeout", 0, iniFileName);
    if (ConnectResults->lan_pair_timeout_min < 0)
        ConnectResults->lan_pair_timeout_min = 0;
    ConnectResults->lan_pair_trusted_installer = IniGetInt(DisplayName, "lanparti", 0, iniFileName) != 0;
    ConnectResults->trycustomlistcommand = 2;

    ConnectResults->detailedlog = IniGetInt(DisplayName, "detailedlog", 0, iniFileName) != 0;
    ConnectResults->utf8names = IniGetInt(DisplayName, "utf8", -1, iniFileName);
    ConnectResults->codepage = IniGetInt(DisplayName, "codepage", 0, iniFileName);
    // One Windows does not know (a hand edit, a file from another machine)
    // would fail every conversion: the system codepage is used instead.
    if (ConnectResults->codepage != 0 && !IsValidCodePage(static_cast<UINT>(ConnectResults->codepage)))
        ConnectResults->codepage = 0;
    ConnectResults->unixlinebreaks = IniGetInt(DisplayName, "unixlinebreaks", -1, iniFileName);
    ConnectResults->scpserver64bit = IniGetInt(DisplayName, "largefilesupport", -1, iniFileName);
    // Loaded whatever the agent setting says: the key file and the password
    // are tried after the agent, and the dialog writes back what it shows.
    ConnectResults->password = LoadPasswordSetting(DisplayName, "password", iniFileName);
    ConnectResults->proxynr = IniGetInt(DisplayName, "proxynr", 0, iniFileName);

    LoadProxySettingsFromNr(ConnectResults->proxynr, ConnectResults, iniFileName);

    // -----------------------------------------------------------------------
    // Jump host (ProxyJump) settings
    // -----------------------------------------------------------------------
    ConnectResults->use_jump_host = IniGetInt(DisplayName, "usejumphost", 0, iniFileName) != 0;
    {
        ConnectResults->jump_host        = IniGetValue(DisplayName, "jumphost", iniFileName);
        ConnectResults->jump_user        = IniGetValue(DisplayName, "jumpuser", iniFileName);
        ConnectResults->jump_pubkeyfile  = IniGetValue(DisplayName, "jumppubkeyfile", iniFileName);
        ConnectResults->jump_privkeyfile = IniGetValue(DisplayName, "jumpprivkeyfile", iniFileName);
        ConnectResults->jump_fingerprint = IniGetValue(DisplayName, "jumpfingerprint", iniFileName);
        const int jumpPort = static_cast<int>(IniGetInt(DisplayName, "jumpport", 22, iniFileName));
        ConnectResults->jump_port        = static_cast<unsigned short>(
            jumpPort > 0 && jumpPort <= 65535 ? jumpPort : 22);
        ConnectResults->jump_useagent    = IniGetInt(DisplayName, "jumpuseagent", 0, iniFileName) != 0;
        ConnectResults->jump_session_ref  = IniGetValue(DisplayName, "jumpsessionref", iniFileName);

        ConnectResults->jump_password = LoadPasswordSetting(DisplayName, "jumppassword", iniFileName);
    }

    ConnectResults->neednewchannel = false;
    ConnectResults->connectsendcommand = IniGetValue(DisplayName, "sendcommand", iniFileName);
    ConnectResults->sendcommandmode = IniGetInt(DisplayName, "sendcommandmode", 0, iniFileName);
    ConnectResults->sftpservercommand = IniGetValue(DisplayName, "sftpservercommand", iniFileName);
    return !ConnectResults->server.empty();
}


void UpdateJumpRefsOnSessionRename(LPCSTR oldName, LPCSTR newName, LPCSTR iniFileName)
{
    if (!oldName || !oldName[0] || !iniFileName || !iniFileName[0])
        return;

    for (const std::string& section : IniSectionNameList(iniFileName)) {
        const char* p = section.c_str();
        std::array<char, MAX_PATH> currentRef{};
        IniGetString(p, "jumpsessionref", "",
                     currentRef.data(),
                     static_cast<DWORD>(currentRef.size()),
                     iniFileName);
        if (currentRef[0] && _stricmp(currentRef.data(), oldName) == 0) {
            // Exact match — rewrite (or clear if newName is null/empty).
            if (newName && newName[0])
                IniWriteString(p, "jumpsessionref", newName, iniFileName);
            else
                IniWriteString(p, "jumpsessionref", nullptr, iniFileName);
        }
    }
}


// ===========================================================================
// Import custom paths — [Imports] section
// ===========================================================================

namespace {

constexpr const char* kImportsSection = "Imports";

// Strip trailing `\` and `/` so equivalent paths normalise before dedup and
// remove-match comparisons.
std::string NormaliseImportPath(std::string_view s) noexcept
{
    while (!s.empty() && (s.back() == '\\' || s.back() == '/'))
        s.remove_suffix(1);
    return std::string(s);
}

// Split "a|b|c" into {"a","b","c"} (empty segments discarded, whitespace
// preserved — folder names may contain them). Accepts both `|` (current)
// and `;` (older stored form) as separators so a pre-existing INI value
// migrates transparently on the next save; `|` is illegal in Windows paths
// while `;` is not, so `|` is the only fully safe choice going forward.
std::vector<std::string> SplitByPipe(std::string_view value)
{
    std::vector<std::string> out;
    size_t start = 0;
    while (start <= value.size()) {
        const size_t sep = value.find_first_of("|;", start);
        const size_t end = (sep == std::string_view::npos) ? value.size() : sep;
        if (end > start)
            out.emplace_back(value.substr(start, end - start));
        if (sep == std::string_view::npos)
            break;
        start = sep + 1;
    }
    return out;
}

std::string JoinByPipe(const std::vector<std::string>& parts)
{
    std::string out;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i) out.push_back('|');
        out.append(parts[i]);
    }
    return out;
}

std::string PathsKey(LPCSTR sourceId)
{
    std::string key(sourceId ? sourceId : "");
    key.append(".custom_paths");
    return key;
}

}  // namespace

std::vector<std::string> LoadImportCustomPaths(LPCSTR sourceId, LPCSTR iniFileName)
{
    if (!sourceId || !sourceId[0] || !iniFileName || !iniFileName[0])
        return {};
    // Custom paths list can be long; oversize the buffer generously vs
    // MAX_PATH so tens of concatenated paths fit.
    std::array<char, 8192> buf{};
    IniGetString(kImportsSection, PathsKey(sourceId).c_str(), "",
                 buf.data(), static_cast<DWORD>(buf.size() - 1),
                 iniFileName);
    return SplitByPipe(buf.data());
}

bool SaveImportCustomPath(LPCSTR sourceId, LPCSTR path, LPCSTR iniFileName)
{
    if (!sourceId || !sourceId[0] || !path || !path[0] ||
        !iniFileName || !iniFileName[0])
        return false;

    const std::string normalized = NormaliseImportPath(path);
    if (normalized.empty())
        return false;

    std::vector<std::string> paths = LoadImportCustomPaths(sourceId, iniFileName);

    // Case-insensitive dedup — Windows paths compare that way.
    const auto exists = std::any_of(paths.begin(), paths.end(),
        [&](const std::string& p) {
            return _stricmp(NormaliseImportPath(p).c_str(), normalized.c_str()) == 0;
        });
    if (exists)
        return true;  // Already registered; treat as successful no-op.

    paths.push_back(normalized);
    const std::string joined = JoinByPipe(paths);
    return IniWriteString(kImportsSection,
        PathsKey(sourceId).c_str(),
        joined.empty() ? nullptr : joined.c_str(),
        iniFileName) != 0;
}

bool RemoveImportCustomPath(LPCSTR sourceId, LPCSTR path, LPCSTR iniFileName)
{
    if (!sourceId || !sourceId[0] || !path || !path[0] ||
        !iniFileName || !iniFileName[0])
        return false;

    const std::string normalized = NormaliseImportPath(path);
    std::vector<std::string> paths = LoadImportCustomPaths(sourceId, iniFileName);

    const auto before = paths.size();
    paths.erase(std::remove_if(paths.begin(), paths.end(),
        [&](const std::string& p) {
            return _stricmp(NormaliseImportPath(p).c_str(), normalized.c_str()) == 0;
        }), paths.end());
    if (paths.size() == before)
        return false;  // Nothing removed.

    const std::string joined = JoinByPipe(paths);
    return IniWriteString(kImportsSection,
        PathsKey(sourceId).c_str(),
        joined.empty() ? nullptr : joined.c_str(),
        iniFileName) != 0;
}
