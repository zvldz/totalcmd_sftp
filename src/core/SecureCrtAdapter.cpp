#include "SecureCrtAdapter.h"
#include "ImportIoUtil.h"
#include "VanDykeIniParser.h"
#include "SftpClient.h"

#define WIN32_LEAN_AND_MEAN
#include <shlobj.h>
#include <windows.h>

#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

namespace sftp {

namespace {

// VanDyke's own default templates / folder metadata — never real sessions.
bool IsSkippableFileName(const char* name) noexcept
{
    return _stricmp(name, "__FolderData__.ini")     == 0
        || _stricmp(name, "Default.ini")            == 0
        || _stricmp(name, "Default_LocalShell.ini") == 0
        || _stricmp(name, "Default_RDP.ini")        == 0
        || _stricmp(name, "Default_Serial.ini")     == 0
        || _stricmp(name, "LocalShell.ini")         == 0;
}

// Resolves %APPDATA%\VanDyke\Config\Sessions.
std::string GetStandardSessionsRoot()
{
    wchar_t wpath[MAX_PATH] = {};
    if (SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, 0, wpath) != S_OK)
        return {};
    char utf8[MAX_PATH * 4] = {};
    WideCharToMultiByte(CP_UTF8, 0, wpath, -1, utf8, sizeof(utf8), nullptr, nullptr);
    return std::string(utf8) + "\\VanDyke\\Config\\Sessions";
}

// Convert a UTF-8 path to wide for a Win32 filesystem call.
std::wstring ToWide(const std::string& s)
{
    const int wchars = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (wchars <= 0) return {};
    std::wstring out(static_cast<size_t>(wchars - 1), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, out.data(), wchars);
    return out;
}

// True if a filesystem path exists (file or directory).
bool PathExistsW(const std::wstring& wpath)
{
    return GetFileAttributesW(wpath.c_str()) != INVALID_FILE_ATTRIBUTES;
}

// Collect every SSH2 session under `root` into `out`. `sourceOrigin` becomes
// the CachedSessionRef channel tag (either "standard" or the literal custom
// path). No file name is reserved beyond the VanDyke defaults filtered by
// IsSkippableFileName.
void CollectSessions(const std::string& root,
                     const std::string& sourceOrigin,
                     std::vector<ExternalSessionEntry>& out)
{
    WalkDirectoryFiles(ToWide(root), L"ini",
        [&](const std::wstring& fullPathW, const std::string& relPath) {
            // Extract the leaf name to run the skip-list check.
            const size_t slash = fullPathW.find_last_of(L"\\/");
            const std::wstring leafW = (slash == std::wstring::npos)
                ? fullPathW : fullPathW.substr(slash + 1);
            char leafU8[MAX_PATH * 4] = {};
            WideCharToMultiByte(CP_UTF8, 0, leafW.c_str(), -1,
                leafU8, sizeof(leafU8), nullptr, nullptr);
            if (IsSkippableFileName(leafU8))
                return true;

            char pathU8[MAX_PATH * 4] = {};
            WideCharToMultiByte(CP_UTF8, 0, fullPathW.c_str(), -1,
                pathU8, sizeof(pathU8), nullptr, nullptr);
            const VanDykeFile file = ParseVanDykeFile(pathU8);
            if (file.empty())
                return true;

            // SSH2 only — other protocols are surfaced by other adapters or
            // not at all.
            const std::string protocol = GetString(file, "Protocol Name");
            if (_stricmp(protocol.c_str(), "SSH2") != 0)
                return true;

            ExternalSessionEntry e;
            e.displayName  = relPath;
            e.sourceOrigin = sourceOrigin;
            out.push_back(std::move(e));
            return true;
        });
}

// Reverse the DisplayName-to-file mapping. DisplayName segments map 1:1
// to on-disk folder segments (no name is treated as reserved). Returns
// empty on miss.
std::string ResolveSessionPath(const std::string& channelRoot,
                                const std::string& displayName)
{
    std::string rel = displayName;
    std::replace(rel.begin(), rel.end(), '/', '\\');
    rel += ".ini";
    const std::string direct = channelRoot + "\\" + rel;
    return PathExistsW(ToWide(direct)) ? direct : std::string{};
}

// Copy the connect fields SecureCRT exposes into `out`. Password / proxy /
// jump-host details are intentionally not touched; the plugin surfaces the
// standard interactive prompt for those when the session first connects.
void FillConnectSettings(const VanDykeFile& file, tConnectSettings* out)
{
    if (!out) return;

    const std::string host = GetString(file, "Hostname");
    const uint32_t    port = GetDWord (file, "[SSH2] Port", 22);
    if (!host.empty()) {
        out->server = (port != 22 && port != 0)
            ? (host + ":" + std::to_string(port))
            : host;
    }

    out->user        = GetString(file, "Username");
    // Same route as the other adapters: expand any %VARS% first, then let
    // the shared helper decide public vs private by extension.
    AssignImportedKeyFile(ExpandEnvA(GetString(file, "Identity Filename V2")),
                          out->privkeyfile, out->pubkeyfile);

    // "Output Transformer Name" = "UTF-8" is the common modern encoding.
    // Anything else we leave as auto-detect (-1, which is the default).
    if (_stricmp(GetString(file, "Output Transformer Name").c_str(), "UTF-8") == 0)
        out->utf8names = 1;
}

}  // namespace

bool SecureCrtAdapter::DetectStandard() const noexcept
{
    const std::string root = GetStandardSessionsRoot();
    if (root.empty()) return false;
    return PathExistsW(ToWide(root + "\\Default.ini"));
}

EnumerationResult SecureCrtAdapter::EnumerateStandard()
{
    EnumerationResult r;
    const std::string root = GetStandardSessionsRoot();
    if (root.empty() || !DetectStandard()) {
        r.status = EnumerationStatus::Unreachable;
        return r;
    }
    CollectSessions(root, "standard", r.sessions);
    r.status = r.sessions.empty()
        ? EnumerationStatus::OkEmpty
        : EnumerationStatus::OkWithSessions;
    return r;
}

EnumerationResult SecureCrtAdapter::EnumerateCustomPath(const std::string& path)
{
    EnumerationResult r;
    const std::wstring wpath = ToWide(path);
    const DWORD attrs = GetFileAttributesW(wpath.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES || !(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        r.status = EnumerationStatus::Unreachable;
        return r;
    }
    CollectSessions(path, path, r.sessions);
    r.status = r.sessions.empty()
        ? EnumerationStatus::OkEmpty
        : EnumerationStatus::OkWithSessions;
    return r;
}

bool SecureCrtAdapter::LoadSettings(const ExternalSessionEntry& entry,
                                     pConnectSettings out)
{
    if (!out) return false;

    // sourceOrigin identifies which channel produced this entry.
    // "standard" → standard %APPDATA% root; everything else is a literal
    // custom-path stored verbatim during enumeration.
    const std::string channelRoot = (entry.sourceOrigin == "standard")
        ? GetStandardSessionsRoot()
        : entry.sourceOrigin;
    if (channelRoot.empty()) return false;

    const std::string path = ResolveSessionPath(channelRoot, entry.displayName);
    if (path.empty()) return false;

    const VanDykeFile file = ParseVanDykeFile(path);
    if (file.empty()) return false;

    FillConnectSettings(file, out);
    return true;
}

}  // namespace sftp
