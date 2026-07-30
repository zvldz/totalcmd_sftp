#include "global.h"
#include <windows.h>
#include <algorithm>
#include <array>
#include <format>
#include <sstream>
#include <string_view>
#include "SftpClient.h"
#include "SftpInternal.h"
#include "ConnectionDialog.h"
#include "ProfileSettings.h"

bool LoadProxySettingsFromNr(int proxynr, pConnectSettings ConnectResults, LPCSTR iniFileName)
{
    if (proxynr > 0) {
        const std::string proxyentry = proxynr > 1 ? std::format("proxy{}", proxynr) : "proxy";
        ConnectResults->proxytype = sftp::Proxy::notused;
        int type = GetPrivateProfileInt(proxyentry.data(), "proxytype", -1, iniFileName);
        if (type >= 0)
            ConnectResults->proxytype = (sftp::Proxy)type;
        std::array<char, MAX_PATH> proxyServer{};
        std::array<char, MAX_PATH> proxyUser{};
        GetPrivateProfileString(proxyentry.data(), "proxyserver", "", proxyServer.data(), proxyServer.size() - 1, iniFileName);
        GetPrivateProfileString(proxyentry.data(), "proxyuser", "", proxyUser.data(), proxyUser.size() - 1, iniFileName);
        ConnectResults->proxyserver = proxyServer.data();
        ConnectResults->proxyuser = proxyUser.data();
        std::array<char, 1024> szPassword{};
        if (GetPrivateProfileString(proxyentry.data(), "proxypassword", "", szPassword.data(), szPassword.size(), iniFileName)) {
            std::array<char, MAX_PATH> decPassword{};
            DecryptString(szPassword.data(), decPassword.data(), static_cast<UINT>(decPassword.size()));
            ConnectResults->proxypassword = decPassword.data();
        } else
            ConnectResults->proxypassword.clear();
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
    std::array<char, 1024> szPassword{};
    std::array<char, 6> modbuf{};
    ConnectResults->DisplayName = DisplayName ? DisplayName : "";
    ConnectResults->IniFileName = iniFileName ? iniFileName : "";
    std::array<char, MAX_PATH> serverBuf{};
    GetPrivateProfileString(DisplayName, "server", "", serverBuf.data(), serverBuf.size() - 1, iniFileName);
    ConnectResults->server = serverBuf.data();
    ConnectResults->protocoltype=GetPrivateProfileInt(DisplayName, "protocol", 0, iniFileName);
    ConnectResults->transfermode = GetPrivateProfileInt(DisplayName, "transfermode", 0, iniFileName);
    if (ConnectResults->transfermode < 0 || ConnectResults->transfermode > 3)
        ConnectResults->transfermode = 0;
    std::array<char, MAX_PATH> userBuf{};
    std::array<char, MAX_PATH> fingerprintBuf{};
    std::array<char, MAX_PATH> pubKeyBuf{};
    std::array<char, MAX_PATH> privKeyBuf{};
    GetPrivateProfileString(DisplayName, "user", "", userBuf.data(), userBuf.size() - 1, iniFileName);
    GetPrivateProfileString(DisplayName, "fingerprint", "", fingerprintBuf.data(), fingerprintBuf.size() - 1, iniFileName);
    GetPrivateProfileString(DisplayName, "pubkeyfile", "", pubKeyBuf.data(), pubKeyBuf.size() - 1, iniFileName);
    GetPrivateProfileString(DisplayName, "privkeyfile", "", privKeyBuf.data(), privKeyBuf.size() - 1, iniFileName);
    ConnectResults->user = userBuf.data();
    ConnectResults->savedfingerprint = fingerprintBuf.data();
    ConnectResults->pubkeyfile = pubKeyBuf.data();
    ConnectResults->privkeyfile = privKeyBuf.data();
    ConnectResults->useagent = GetPrivateProfileInt(DisplayName, "useagent", 0, iniFileName) != 0;

    GetPrivateProfileString(DisplayName, "filemod", "644", modbuf.data(), modbuf.size() - 1, iniFileName);
    ConnectResults->filemod = strtol(modbuf.data(), nullptr, 8);
    GetPrivateProfileString(DisplayName, "dirmod", "755", modbuf.data(), modbuf.size() - 1, iniFileName);
    ConnectResults->dirmod = strtol(modbuf.data(), nullptr, 8);

    ConnectResults->compressed = GetPrivateProfileInt(DisplayName, "compression", 0, iniFileName) != 0;
    ConnectResults->scpfordata = GetPrivateProfileInt(DisplayName, "scpfordata", 0, iniFileName) != 0;
    ConnectResults->scponly = GetPrivateProfileInt(DisplayName, "scponly", 0, iniFileName) != 0;
    if (ConnectResults->scponly)
        ConnectResults->scpfordata = true;
    ConnectResults->shell_transfer_dd = GetPrivateProfileInt(DisplayName, "shelltransfer", 0, iniFileName) != 0;
    ConnectResults->shell_transfer_force =
        GetPrivateProfileInt(DisplayName, "shelltransferforce",
                             ConnectResults->shell_transfer_dd ? 1 : 0,
                             iniFileName) != 0;
    ConnectResults->shell_dd_b64only  = false;
    ConnectResults->php_http_mode = GetPrivateProfileInt(DisplayName, "phphttpmode", 0, iniFileName);
    if (ConnectResults->php_http_mode < 0 || ConnectResults->php_http_mode > 2)
        ConnectResults->php_http_mode = 0;
    ConnectResults->php_chunk_mib = GetPrivateProfileInt(DisplayName, "phpchunkmb", 0, iniFileName);
    if (!(ConnectResults->php_chunk_mib == 0 || ConnectResults->php_chunk_mib == 1 ||
          ConnectResults->php_chunk_mib == 2 || ConnectResults->php_chunk_mib == 4 ||
          ConnectResults->php_chunk_mib == 8 || ConnectResults->php_chunk_mib == 16 ||
          ConnectResults->php_chunk_mib == 32 || ConnectResults->php_chunk_mib == 64))
        ConnectResults->php_chunk_mib = 0;
    ConnectResults->php_recommended_chunk_mib = 0;
    ConnectResults->php_tar = GetPrivateProfileInt(DisplayName, "phptar", 0, iniFileName) != 0;
    ConnectResults->lan_pair_role = GetPrivateProfileInt(DisplayName, "lanpairrole", 0, iniFileName);
    if (ConnectResults->lan_pair_role < 0 || ConnectResults->lan_pair_role > 2)
        ConnectResults->lan_pair_role = 0;
    std::array<char, MAX_PATH> lanPeerBuf{};
    GetPrivateProfileString(DisplayName, "lanpairpeer", "", lanPeerBuf.data(), lanPeerBuf.size() - 1, iniFileName);
    ConnectResults->lan_pair_peer = lanPeerBuf.data();
    ConnectResults->lan_pair_timeout_min = GetPrivateProfileInt(DisplayName, "lanpairtimeout", 0, iniFileName);
    if (ConnectResults->lan_pair_timeout_min < 0)
        ConnectResults->lan_pair_timeout_min = 0;
    ConnectResults->lan_pair_trusted_installer = GetPrivateProfileInt(DisplayName, "lanparti", 0, iniFileName) != 0;
    ConnectResults->trycustomlistcommand = 2;

    ConnectResults->detailedlog = GetPrivateProfileInt(DisplayName, "detailedlog", 0, iniFileName) != 0;
    ConnectResults->utf8names = GetPrivateProfileInt(DisplayName, "utf8", -1, iniFileName);
    ConnectResults->codepage = GetPrivateProfileInt(DisplayName, "codepage", 0, iniFileName);
    ConnectResults->unixlinebreaks = GetPrivateProfileInt(DisplayName, "unixlinebreaks", -1, iniFileName);
    ConnectResults->scpserver64bit = GetPrivateProfileInt(DisplayName, "largefilesupport", -1, iniFileName);
    ConnectResults->password.clear();
    if (GetPrivateProfileString(DisplayName, "password", "",  szPassword.data(),  szPassword.size(),  iniFileName)) {
        if (!ConnectResults->useagent) {
            std::array<char, MAX_PATH> decPassword{};
            DecryptString(szPassword.data(), decPassword.data(), static_cast<UINT>(decPassword.size()));
            ConnectResults->password = decPassword.data();
        }
        else if (strcmp(szPassword.data(), "!") == 0)
            ConnectResults->password = "\001";
    }
    ConnectResults->proxynr = GetPrivateProfileInt(DisplayName, "proxynr", 0, iniFileName);

    LoadProxySettingsFromNr(ConnectResults->proxynr, ConnectResults, iniFileName);

    // -----------------------------------------------------------------------
    // Jump host (ProxyJump) settings
    // -----------------------------------------------------------------------
    ConnectResults->use_jump_host = GetPrivateProfileInt(DisplayName, "usejumphost", 0, iniFileName) != 0;
    {
        std::array<char, MAX_PATH> jumpHost{};
        std::array<char, MAX_PATH> jumpUser{};
        std::array<char, MAX_PATH> jumpPub{};
        std::array<char, MAX_PATH> jumpPriv{};
        std::array<char, MAX_PATH> jumpFp{};
        GetPrivateProfileString(DisplayName, "jumphost",       "", jumpHost.data(),  jumpHost.size() - 1,  iniFileName);
        GetPrivateProfileString(DisplayName, "jumpuser",       "", jumpUser.data(),  jumpUser.size() - 1,  iniFileName);
        GetPrivateProfileString(DisplayName, "jumppubkeyfile", "", jumpPub.data(),   jumpPub.size() - 1,   iniFileName);
        GetPrivateProfileString(DisplayName, "jumpprivkeyfile","", jumpPriv.data(),  jumpPriv.size() - 1,  iniFileName);
        GetPrivateProfileString(DisplayName, "jumpfingerprint","", jumpFp.data(),    jumpFp.size() - 1,    iniFileName);
        ConnectResults->jump_host        = jumpHost.data();
        ConnectResults->jump_user        = jumpUser.data();
        ConnectResults->jump_pubkeyfile  = jumpPub.data();
        ConnectResults->jump_privkeyfile = jumpPriv.data();
        ConnectResults->jump_fingerprint = jumpFp.data();
        ConnectResults->jump_port        = static_cast<unsigned short>(
            GetPrivateProfileInt(DisplayName, "jumpport", 22, iniFileName));
        ConnectResults->jump_useagent    = GetPrivateProfileInt(DisplayName, "jumpuseagent", 0, iniFileName) != 0;
        std::array<char, MAX_PATH> jumpSessRef{};
        GetPrivateProfileString(DisplayName, "jumpsessionref", "", jumpSessRef.data(), jumpSessRef.size() - 1, iniFileName);
        ConnectResults->jump_session_ref  = jumpSessRef.data();

        std::array<char, 1024> jumpPass{};
        if (GetPrivateProfileString(DisplayName, "jumppassword", "", jumpPass.data(), jumpPass.size(), iniFileName)) {
            std::array<char, MAX_PATH> decJumpPass{};
            DecryptString(jumpPass.data(), decJumpPass.data(), static_cast<UINT>(decJumpPass.size()));
            ConnectResults->jump_password = decJumpPass.data();
        } else {
            ConnectResults->jump_password.clear();
        }
    }

    ConnectResults->neednewchannel = false;
    std::array<char, MAX_PATH> sendCommandBuf{};
    GetPrivateProfileString(DisplayName, "sendcommand", "", sendCommandBuf.data(), sendCommandBuf.size() - 1, iniFileName);
    ConnectResults->connectsendcommand = sendCommandBuf.data();
    ConnectResults->sendcommandmode = GetPrivateProfileInt(DisplayName, "sendcommandmode", 0, iniFileName);
    return !ConnectResults->server.empty();
}

void ResetProfileFields(pConnectSettings dst)
{
    if (!dst)
        return;

    // Connection
    dst->server.clear();
    dst->user.clear();
    dst->password.clear();
    dst->protocoltype       = 0;
    dst->transfermode       = 0;
    dst->compressed         = false;
    dst->detailedlog        = false;
    dst->connectsendcommand.clear();
    dst->sendcommandmode    = 0;

    // Authentication
    dst->useagent           = false;
    dst->pubkeyfile.clear();
    dst->privkeyfile.clear();
    dst->savedfingerprint.clear();
    dst->account_password.clear();
    dst->key_passphrase.clear();

    // Remote file handling
    dst->filemod            = 0644;
    dst->dirmod             = 0755;
    dst->utf8names          = AUTODETECT_PENDING;
    dst->codepage           = 0;
    dst->unixlinebreaks     = AUTODETECT_PENDING;

    // SCP / shell transfer
    dst->scponly              = false;
    dst->scpfordata           = false;
    dst->scpserver64bit       = AUTODETECT_PENDING;
    dst->shell_transfer_dd    = false;
    dst->shell_transfer_force = false;

    // PHP agent
    dst->php_http_mode      = 0;
    dst->php_chunk_mib      = 0;
    dst->php_tar            = false;

    // LAN pair
    dst->lan_pair_role              = 0;
    dst->lan_pair_peer.clear();
    dst->lan_pair_timeout_min       = 0;
    dst->lan_pair_trusted_installer = false;

    // Proxy
    dst->proxynr            = 0;
    dst->proxytype          = sftp::Proxy::notused;
    dst->proxyserver.clear();
    dst->proxyuser.clear();
    dst->proxypassword.clear();

    // Jump host
    dst->use_jump_host      = false;
    dst->jump_session_ref.clear();
    dst->jump_host.clear();
    dst->jump_port          = 22;
    dst->jump_user.clear();
    dst->jump_password.clear();
    dst->jump_pubkeyfile.clear();
    dst->jump_privkeyfile.clear();
    dst->jump_useagent      = false;
    dst->jump_fingerprint.clear();
    dst->jump_key_passphrase.clear();
}

void AssignProfileFields(pConnectSettings dst, const tConnectSettings& src)
{
    if (!dst)
        return;

    // Connection
    dst->server             = src.server;
    dst->user               = src.user;
    dst->password           = src.password;
    dst->protocoltype       = src.protocoltype;
    dst->transfermode       = src.transfermode;
    dst->compressed         = src.compressed;
    dst->detailedlog        = src.detailedlog;
    dst->connectsendcommand = src.connectsendcommand;
    dst->sendcommandmode    = src.sendcommandmode;

    // Authentication
    dst->useagent           = src.useagent;
    dst->pubkeyfile         = src.pubkeyfile;
    dst->privkeyfile        = src.privkeyfile;
    dst->savedfingerprint   = src.savedfingerprint;

    // Remote file handling
    dst->filemod            = src.filemod;
    dst->dirmod             = src.dirmod;
    dst->utf8names          = src.utf8names;
    dst->codepage           = src.codepage;
    dst->unixlinebreaks     = src.unixlinebreaks;

    // SCP / shell transfer
    dst->scponly              = src.scponly;
    dst->scpfordata           = src.scpfordata;
    dst->scpserver64bit       = src.scpserver64bit;
    dst->shell_transfer_dd    = src.shell_transfer_dd;
    dst->shell_transfer_force = src.shell_transfer_force;

    // PHP agent
    dst->php_http_mode      = src.php_http_mode;
    dst->php_chunk_mib      = src.php_chunk_mib;
    dst->php_tar            = src.php_tar;

    // LAN pair
    dst->lan_pair_role              = src.lan_pair_role;
    dst->lan_pair_peer              = src.lan_pair_peer;
    dst->lan_pair_timeout_min       = src.lan_pair_timeout_min;
    dst->lan_pair_trusted_installer = src.lan_pair_trusted_installer;

    // Proxy
    dst->proxynr            = src.proxynr;
    dst->proxytype          = src.proxytype;
    dst->proxyserver        = src.proxyserver;
    dst->proxyuser          = src.proxyuser;
    dst->proxypassword      = src.proxypassword;

    // Jump host
    dst->use_jump_host      = src.use_jump_host;
    dst->jump_session_ref   = src.jump_session_ref;
    dst->jump_host          = src.jump_host;
    dst->jump_port          = src.jump_port;
    dst->jump_user          = src.jump_user;
    dst->jump_password      = src.jump_password;
    dst->jump_pubkeyfile    = src.jump_pubkeyfile;
    dst->jump_privkeyfile   = src.jump_privkeyfile;
    dst->jump_useagent      = src.jump_useagent;
    dst->jump_fingerprint   = src.jump_fingerprint;
}

void UpdateJumpRefsOnSessionRename(LPCSTR oldName, LPCSTR newName, LPCSTR iniFileName)
{
    if (!oldName || !oldName[0] || !iniFileName || !iniFileName[0])
        return;

    // GetPrivateProfileSectionNames returns section names as a
    // double-null-terminated list. 65535 is the documented hard limit.
    std::array<char, 65535> sectionList{};
    GetPrivateProfileSectionNamesA(sectionList.data(),
                                   static_cast<DWORD>(sectionList.size()),
                                   iniFileName);

    char* p = sectionList.data();
    while (p[0]) {
        std::array<char, MAX_PATH> currentRef{};
        GetPrivateProfileStringA(p, "jumpsessionref", "",
                                 currentRef.data(),
                                 static_cast<DWORD>(currentRef.size()),
                                 iniFileName);
        if (currentRef[0] && _stricmp(currentRef.data(), oldName) == 0) {
            // Exact match — rewrite (or clear if newName is null/empty).
            if (newName && newName[0])
                WritePrivateProfileStringA(p, "jumpsessionref", newName, iniFileName);
            else
                WritePrivateProfileStringA(p, "jumpsessionref", nullptr, iniFileName);
        }
        p += strlen(p) + 1;
    }
}

void UpdateJumpRefsOnFolderRename(LPCSTR oldPrefix, LPCSTR newPrefix, LPCSTR iniFileName)
{
    if (!oldPrefix || !oldPrefix[0] || !newPrefix || !newPrefix[0] ||
        !iniFileName || !iniFileName[0])
        return;

    const std::string oldNeedle = std::string(oldPrefix) + "/";
    const std::string newReplacement = std::string(newPrefix) + "/";

    std::array<char, 65535> sectionList{};
    GetPrivateProfileSectionNamesA(sectionList.data(),
                                   static_cast<DWORD>(sectionList.size()),
                                   iniFileName);

    char* p = sectionList.data();
    while (p[0]) {
        std::array<char, MAX_PATH> currentRef{};
        GetPrivateProfileStringA(p, "jumpsessionref", "",
                                 currentRef.data(),
                                 static_cast<DWORD>(currentRef.size()),
                                 iniFileName);
        const size_t reflen = strlen(currentRef.data());
        if (reflen > oldNeedle.size() &&
            _strnicmp(currentRef.data(), oldNeedle.c_str(), oldNeedle.size()) == 0)
        {
            std::string updated = newReplacement;
            updated.append(currentRef.data() + oldNeedle.size());
            WritePrivateProfileStringA(p, "jumpsessionref", updated.c_str(), iniFileName);
        }
        p += strlen(p) + 1;
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
    GetPrivateProfileStringA(kImportsSection, PathsKey(sourceId).c_str(), "",
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
    return WritePrivateProfileStringA(kImportsSection,
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
    return WritePrivateProfileStringA(kImportsSection,
        PathsKey(sourceId).c_str(),
        joined.empty() ? nullptr : joined.c_str(),
        iniFileName) != 0;
}
