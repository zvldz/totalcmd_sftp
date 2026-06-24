#include <winsock2.h>
#include <windows.h>
#include <stdlib.h>
#include <array>
#include <memory>
#include <string>
#include <string_view>
#include <algorithm>
#include <set>
#include <vector>
#include "fsplugin.h"
#include "CoreUtils.h"
#include "res/resource.h"
#include "SftpClient.h"
#include "SftpInternal.h"
#include "ServerRegistry.h"
#include "UnicodeHelpers.h"
#include "PluginEntryPoints.h"
#include "DllExceptionBarrier.h"
#include "LanPairSession.h"
#include "PluginEntryPointsInternal.h"
#include "PhpAgentClient.h"

// Path of the most recent FsFindFirstW call that returned PATH_NOT_FOUND.
// TC's "paste into a non-existent folder" flow does FsFindFirstW (to check
// existence) → fails → FsMkDir (create the folder) for the same path. By
// remembering that exact path, FsMkDir can recognise the second leg of the
// pattern and skip the new-session dialog, even when TC has not yet fired
// its RENMOV_MULTI status callback (which sometimes comes AFTER the first
// FsMkDir). On user-initiated F7 the previous failed-find path is empty or
// stale (TC didn't pre-check), so the dialog still opens normally.
static std::wstring g_lastFailedFindPath;

// RAII guard for a freshly-established server connection.
// Prevents connection leaks on error paths without manual cleanup pairing.
//
// Registered variant (name non-empty): on rollback, calls SetServerIdForName(nullptr)
//   which closes the session and deletes the settings object via the registry.
// Unregistered variant (name empty): directly calls SftpCloseConnection + delete.
// commit() disarms the guard — ownership is transferred permanently to the registry.
class ConnectionGuard {
public:
    ConnectionGuard(pConnectSettings cs, LPCSTR registeredName) noexcept
        : cs_(cs), name_(registeredName ? registeredName : "") {}

    void commit() noexcept { cs_ = nullptr; }

    ~ConnectionGuard() noexcept {
        if (!cs_) return;
        if (!name_.empty())
            SetServerIdForName(name_.c_str(), nullptr);
        else {
            SftpCloseConnection(cs_);
            delete cs_;
        }
    }

    ConnectionGuard(const ConnectionGuard&) = delete;
    ConnectionGuard& operator=(const ConnectionGuard&) = delete;

private:
    pConnectSettings cs_;
    std::string name_;
};

// ---------------------------------------------------------------------------
// Find handle state types
// ---------------------------------------------------------------------------

struct LanPairFindState {
    std::vector<LanPairSession::DirEntry> entries;
    size_t index = 0;
};

// Plugin-side namespace entry: a saved session, a folder grouping saved
// sessions, the [F7 = new connection] pseudo-helper, or — inside the
// [Active Sessions] magic folder — a live session row / bulk-disconnect
// trigger. Used to render the listing for the plugin root and any folder
// under it.
struct PluginFolderEntry {
    std::string name;
    enum class Kind {
        Folder,         // grouping of saved sessions (FILE_ATTRIBUTE_DIRECTORY)
        Session,        // saved session leaf (IFLNK + UNIXMODE → padlock icon)
        Pseudo,         // [F7 = new connection] help entry
        ActiveSession,  // live session row inside [Active Sessions] (plain file)
        ActiveBulkOp    // [Disconnect All] inside [Active Sessions] (plain file)
    } kind = Kind::Session;
    DWORD       helpFileSize = 0;   // Pseudo only — used as nFileSizeLow.
};

struct PluginFolderFindState {
    std::vector<PluginFolderEntry> entries;
    size_t index = 0;
};

typedef struct {
    LPVOID           sftpdataptr;    /* LIBSSH2_SFTP_HANDLE, SCP_DATA, LanPairFindState*, or PluginFolderFindState* */
    pConnectSettings serverid;
    SERVERHANDLE     rootfindhandle;
    bool             rootfindfirst;
    bool             isLanPair;       /* if true, sftpdataptr is LanPairFindState* */
    bool             isPluginFolder;  /* if true, sftpdataptr is PluginFolderFindState* */
} tLastFindStuct, *pLastFindStuct;

static HANDLE CreateLastFindHandle(LPVOID sftpdataptr, pConnectSettings serverid, bool rootfindfirst) noexcept
{
    auto lfMem = std::make_unique<tLastFindStuct>();
    lfMem->sftpdataptr = sftpdataptr;
    lfMem->serverid = serverid;
    lfMem->rootfindhandle = nullptr;
    lfMem->rootfindfirst = rootfindfirst;
    lfMem->isLanPair = false;
    lfMem->isPluginFolder = false;
    return static_cast<HANDLE>(lfMem.release());
}

// ---------------------------------------------------------------------------
// LAN Pair helpers for directory enumeration
// ---------------------------------------------------------------------------

// Convert a wide TC remote path to a UTF-8 Windows path for the LAN protocol.
// TC uses backslash separators; the remote side expects Windows paths directly.
std::string LanRemotePathToUtf8(LPCWSTR remotedir)
{
    if (!remotedir || !remotedir[0])
        return "\\";
    int needed = WideCharToMultiByte(CP_UTF8, 0, remotedir, -1, nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return "\\";
    std::string s(needed - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, remotedir, -1, s.data(), needed, nullptr, nullptr);
    return s;
}

// Fill a WIN32_FIND_DATAW from a LAN Pair DirEntry.
static void LanFillFindData(WIN32_FIND_DATAW* fd, const LanPairSession::DirEntry& e)
{
    *fd = {};
    MultiByteToWideChar(CP_UTF8, 0, e.name.c_str(), -1,
                        fd->cFileName, static_cast<int>(MAX_PATH - 1));
    fd->ftLastWriteTime = e.lastWrite;
    fd->dwFileAttributes = e.isDir ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL;
    if (e.winAttrs)
        fd->dwFileAttributes = e.winAttrs;
    if (!e.isDir) {
        fd->nFileSizeLow  = static_cast<DWORD>(e.size & 0xFFFFFFFF);
        fd->nFileSizeHigh = static_cast<DWORD>((e.size >> 32) & 0xFFFFFFFF);
    }
}

// Create a find handle for a LAN Pair directory result.
static HANDLE LanCreateFindHandle(std::vector<LanPairSession::DirEntry> entries,
                                  WIN32_FIND_DATAW* FindData,
                                  pConnectSettings serverid)
{
    auto state = std::make_unique<LanPairFindState>();
    state->entries = std::move(entries);
    state->index   = 0;

    auto lf = std::make_unique<tLastFindStuct>();
    lf->serverid      = serverid;
    lf->rootfindhandle = nullptr;
    lf->rootfindfirst  = false;
    lf->isLanPair      = true;
    lf->isPluginFolder = false;

    if (state->entries.empty()) {
        lf->sftpdataptr = state.release();
        SetLastError(ERROR_NO_MORE_FILES);
        // Return a valid handle so TC calls FindClose — even if no files.
        return static_cast<HANDLE>(lf.release());
    }

    LanFillFindData(FindData, state->entries[0]);
    state->index = 1;
    lf->sftpdataptr = state.release();
    return static_cast<HANDLE>(lf.release());
}

// ---------------------------------------------------------------------------
// Plugin-side folder enumeration
// ---------------------------------------------------------------------------

namespace {

struct CaseInsensitiveLess {
    bool operator()(const std::string& a, const std::string& b) const noexcept {
        return _stricmp(a.c_str(), b.c_str()) < 0;
    }
};

}  // anonymous namespace

// Fill a WIN32_FIND_DATAW from one PluginFolderEntry. Pseudo entries advertise
// the help-file body length so TC's viewer sizes correctly; folder entries
// carry FILE_ATTRIBUTE_DIRECTORY; saved sessions keep the legacy IFLNK
// rendering so F8 (delete) and Enter (open) behave the same as before
// folders existed.
static void FillFindDataFromPluginEntry(WIN32_FIND_DATAW& fd, const PluginFolderEntry& e)
{
    fd = {};
    awlcopy(fd.cFileName, e.name.c_str(), countof(fd.cFileName) - 1);
    SetInt64ToFileTime(&fd.ftLastWriteTime, FS_TIME_UNKNOWN);
    switch (e.kind) {
        case PluginFolderEntry::Kind::Pseudo:
            fd.dwFileAttributes = 0;
            fd.nFileSizeLow = e.helpFileSize;
            break;
        case PluginFolderEntry::Kind::Folder:
            fd.dwFileAttributes = FILE_ATTRIBUTE_DIRECTORY;
            break;
        case PluginFolderEntry::Kind::Session:
            fd.dwFileAttributes = FS_ATTR_UNIXMODE;
            fd.dwReserved0 = LIBSSH2_SFTP_S_IFLNK;
            break;
        case PluginFolderEntry::Kind::ActiveSession:
        case PluginFolderEntry::Kind::ActiveBulkOp:
            // Plain-file rendering so Enter does nothing (the row is just a
            // disconnect target) and F8 reaches FsDeleteFileW unambiguously.
            fd.dwFileAttributes = FILE_ATTRIBUTE_NORMAL;
            break;
    }
}

// Build a synthetic listing for the plugin namespace at `folderPrefix` (empty
// string means root). The first entry is filled into FindData; remaining
// entries live in the returned find handle for FsFindNextW to walk.
//
// Algorithm: enumerate g_servers via the existing flat API, then for each
// saved session that lies under `folderPrefix`, classify the next path
// segment as either a leaf session (no further slash) or a subfolder
// (de-duped). Folder wins on a name collision — a saved session whose name
// equals a folder name is omitted from the listing (the user can resolve
// the clash by renaming one side).
static HANDLE BuildPluginFolderListing(const std::string& folderPrefix,
                                       WIN32_FIND_DATAW* FindData)
{
    auto state = std::make_unique<PluginFolderFindState>();
    const bool isRoot = folderPrefix.empty();

    // Pseudo-entry [F7 = new connection] lives only at the root.
    if (isRoot) {
        std::array<char, 256> helpText{};
        LoadString(hinst, IDS_HELPTEXT, helpText.data(), static_cast<int>(helpText.size()));
        PluginFolderEntry pe;
        pe.name = s_f7newconnection;
        pe.kind = PluginFolderEntry::Kind::Pseudo;
        pe.helpFileSize = static_cast<DWORD>(strlen(helpText.data()));
        state->entries.push_back(std::move(pe));
    }

    std::set<std::string, CaseInsensitiveLess> foldersSeen;
    std::vector<PluginFolderEntry> sessions;
    std::vector<PluginFolderEntry> subfolders;
    bool hasActiveSession = false;
    {
        std::array<char, wdirtypemax> nameBuf{};
        SERVERHANDLE hdl = FindFirstServer(nameBuf.data(), nameBuf.size() - 1);
        while (hdl) {
            std::string fullName = nameBuf.data();
            // Track whether any session is currently connected — used at root
            // to decide whether to surface the [Active Sessions] magic folder.
            if (isRoot && !hasActiveSession &&
                GetServerIdFromName(fullName.c_str(), GetCurrentThreadId()) != nullptr) {
                hasActiveSession = true;
            }
            std::string relative;
            bool include = false;
            if (isRoot) {
                include = true;
                relative = fullName;
            } else {
                const std::string needle = folderPrefix + "/";
                if (fullName.size() > needle.size() &&
                    _strnicmp(fullName.c_str(), needle.c_str(), needle.size()) == 0) {
                    include = true;
                    relative = fullName.substr(needle.size());
                }
            }
            if (include) {
                const size_t slashPos = relative.find('/');
                if (slashPos == std::string::npos) {
                    PluginFolderEntry e;
                    e.name = std::move(relative);
                    e.kind = PluginFolderEntry::Kind::Session;
                    sessions.push_back(std::move(e));
                } else {
                    std::string sub = relative.substr(0, slashPos);
                    if (foldersSeen.insert(sub).second) {
                        PluginFolderEntry e;
                        e.name = std::move(sub);
                        e.kind = PluginFolderEntry::Kind::Folder;
                        subfolders.push_back(std::move(e));
                    }
                }
            }
            nameBuf[0] = 0;
            hdl = FindNextServer(hdl, nameBuf.data(), nameBuf.size() - 1);
        }
    }

    // Folder wins on a name collision.
    sessions.erase(std::remove_if(sessions.begin(), sessions.end(),
        [&](const PluginFolderEntry& s) { return foldersSeen.contains(s.name); }),
        sessions.end());

    // At root, if anything is currently connected, expose the magic
    // [Active Sessions] folder right after the F7 helper entry so the user
    // can see and disconnect open sessions without tab-juggling.
    if (isRoot && hasActiveSession) {
        PluginFolderEntry active;
        active.name = kActiveSessionsFolder;
        active.kind = PluginFolderEntry::Kind::Folder;
        state->entries.push_back(std::move(active));
    }

    // Folders first (TC convention), then leaf sessions.
    for (auto& e : subfolders) state->entries.push_back(std::move(e));
    for (auto& e : sessions)   state->entries.push_back(std::move(e));

    auto lf = std::make_unique<tLastFindStuct>();
    lf->sftpdataptr    = state.release();
    lf->serverid       = nullptr;
    lf->rootfindhandle = nullptr;
    lf->rootfindfirst  = false;
    lf->isLanPair      = false;
    lf->isPluginFolder = true;

    auto* st = static_cast<PluginFolderFindState*>(lf->sftpdataptr);
    if (st->entries.empty()) {
        SetLastError(ERROR_NO_MORE_FILES);
        return static_cast<HANDLE>(lf.release());  // valid handle so FindClose runs
    }
    FillFindDataFromPluginEntry(*FindData, st->entries[0]);
    st->index = 1;
    return static_cast<HANDLE>(lf.release());
}

// Build a synthetic listing for the [Active Sessions] magic folder. First row
// is a bulk [Disconnect All]; remaining rows are every currently-connected
// session by its full DisplayName (folder-nested sessions keep their slashes,
// so a row reads e.g. "home/raspi" — flat, one F8 away from disconnect).
static HANDLE BuildActiveSessionsListing(WIN32_FIND_DATAW* FindData)
{
    auto state = std::make_unique<PluginFolderFindState>();

    // Active sessions first; [Disconnect All] only appears when at least one
    // session is connected (an empty listing after F8 simply leaves the user
    // with TC's `..` parent entry to back out).
    std::array<char, wdirtypemax> nameBuf{};
    SERVERHANDLE hdl = FindFirstServer(nameBuf.data(), nameBuf.size() - 1);
    while (hdl) {
        if (GetServerIdFromName(nameBuf.data(), GetCurrentThreadId()) != nullptr) {
            PluginFolderEntry e;
            e.name = nameBuf.data();
            e.kind = PluginFolderEntry::Kind::ActiveSession;
            state->entries.push_back(std::move(e));
        }
        nameBuf[0] = 0;
        hdl = FindNextServer(hdl, nameBuf.data(), nameBuf.size() - 1);
    }
    if (!state->entries.empty()) {
        PluginFolderEntry bulk;
        bulk.name = kDisconnectAllEntry;
        bulk.kind = PluginFolderEntry::Kind::ActiveBulkOp;
        state->entries.insert(state->entries.begin(), std::move(bulk));
    }

    auto lf = std::make_unique<tLastFindStuct>();
    lf->sftpdataptr    = state.release();
    lf->serverid       = nullptr;
    lf->rootfindhandle = nullptr;
    lf->rootfindfirst  = false;
    lf->isLanPair      = false;
    lf->isPluginFolder = true;

    auto* st = static_cast<PluginFolderFindState*>(lf->sftpdataptr);
    if (st->entries.empty()) {
        SetLastError(ERROR_NO_MORE_FILES);
        return static_cast<HANDLE>(lf.release());
    }
    FillFindDataFromPluginEntry(*FindData, st->entries[0]);
    st->index = 1;
    return static_cast<HANDLE>(lf.release());
}

// See PluginEntryPointsInternal.h for the contract.
bool IsActiveSessionsPath(LPCWSTR path, std::string* outEntry)
{
    if (!path || path[0] != L'\\') return false;
    const std::wstring_view view(path + 1);  // strip leading '\\'
    const std::wstring_view magic(kActiveSessionsFolderW);
    if (view.size() < magic.size()) return false;
    if (_wcsnicmp(view.data(), magic.data(), magic.size()) != 0) return false;
    const std::wstring_view after = view.substr(magic.size());
    if (after.empty() || (after.size() == 1 && (after[0] == L'\\' || after[0] == L'/'))) {
        if (outEntry) outEntry->clear();
        return true;
    }
    if (after[0] != L'\\' && after[0] != L'/') return false;
    if (outEntry) {
        std::wstring_view trail = after.substr(1);
        // Convert to narrow ANSI and replace any '\' with '/' so folder-
        // nested DisplayNames round-trip cleanly.
        const int needed = WideCharToMultiByte(CP_ACP, 0, trail.data(),
                                                static_cast<int>(trail.size()),
                                                nullptr, 0, nullptr, nullptr);
        outEntry->assign(needed > 0 ? static_cast<size_t>(needed) : 0, '\0');
        if (needed > 0) {
            WideCharToMultiByte(CP_ACP, 0, trail.data(),
                                 static_cast<int>(trail.size()),
                                 outEntry->data(), needed, nullptr, nullptr);
        }
        std::replace(outEntry->begin(), outEntry->end(), '\\', '/');
    }
    return true;
}

HANDLE WINAPI FsFindFirstW(LPCWSTR Path, LPWIN32_FIND_DATAW FindData)
{
    sftp::DllExceptionBarrier _barrier;
    SFTP_LOG("FIND", "FsFindFirstW ENTRY path='%S'", Path ? Path : L"(null)");
    return sftp::dll_invoke(_barrier, INVALID_HANDLE_VALUE, [&]() -> HANDLE {
        int hr = ERROR_SUCCESS;
        std::array<WCHAR, wdirtypemax> remotedir{};
        std::array<char, wdirtypemax> displayName{};
        std::array<char, wdirtypemax> pathA{};

        if (wcscmp(Path, L"\\") == 0) {  // in the root.
            ApplyTcLanguageToPluginResources(g_wincmdIniPath);
            LoadServersFromIniW(inifilenameW, s_quickconnect);
            *FindData = {};
            return BuildPluginFolderListing(std::string{}, FindData);
        }

        // [Active Sessions] magic folder — synthetic listing of currently
        // connected sessions. Detected before the resolver because the path
        // doesn't correspond to any saved session and would otherwise fall
        // through into the implicit-connect branch.
        {
            std::string trailingEntry;
            if (IsActiveSessionsPath(Path, &trailingEntry) && trailingEntry.empty()) {
                LoadServersFromIniW(inifilenameW, s_quickconnect);
                *FindData = {};
                return BuildActiveSessionsListing(FindData);
            }
        }

        // Plugin-side folder navigation: the path is not a real session but a
        // grouping prefix that contains at least one saved session. Resolver
        // classifies this as PathKind::Folder with a non-empty displayName.
        // Refresh the in-memory session list first so the resolver sees any
        // sessions saved since the last enumeration.
        LoadServersFromIniW(inifilenameW, s_quickconnect);
        {
            const PathResolution r = ResolvePathKindW(Path);
            if (r.kind == PathKind::Folder && !r.displayName.empty()) {
                *FindData = {};
                return BuildPluginFolderListing(r.displayName, FindData);
            }
        }

        pConnectSettings serverid = nullptr;
        pConnectSettings new_serverid = nullptr;
        LPVOID sftpdataptr = nullptr;

        // load server list if user connects directly via URL
        LoadServersFromIniW(inifilenameW, s_quickconnect);
        // Disable reading only within an active server context.
        if (disablereading && IsMainThread()) {
            SetLastError(ERROR_NO_MORE_FILES);
            return INVALID_HANDLE_VALUE;
        }
        walcopy(pathA.data(), Path, pathA.size() - 1);
        GetDisplayNameFromPath(pathA.data(), displayName.data(), displayName.size() - 1);
        serverid = static_cast<pConnectSettings>(GetServerIdFromName(displayName.data(), GetCurrentThreadId()));
        bool wasconnected = serverid != nullptr;
        if (!wasconnected) {
            // During a TC multi-step transfer (RENMOV_MULTI), an unresolved
            // path is almost always TC probing a destination as part of its
            // check-then-create flow — NOT a quick-connect URL the user
            // typed. SftpConnectToServer would open the new-session dialog
            // here (empty fields because nothing is in INI), which is the
            // confusing popup the user reported. Short-circuit: remember the
            // path for FsMkDirW to recognise as the immediate next call, and
            // report "path not found" without prompting.
            if (g_inMultiOpTransfer) {
                g_lastFailedFindPath = Path;
                SetLastError(ERROR_PATH_NOT_FOUND);
                return INVALID_HANDLE_VALUE;
            }
            new_serverid = SftpConnectToServer(displayName.data(), inifilename, nullptr);
            if (!new_serverid) {
                // Remember this path so FsMkDirW can recognise the TC
                // "check-then-create" copy/move flow that immediately follows.
                g_lastFailedFindPath = Path;
                SetLastError(ERROR_PATH_NOT_FOUND);
                return INVALID_HANDLE_VALUE;
            }
            serverid = new_serverid;
            SetServerIdForName(displayName.data(), static_cast<SERVERID>(serverid));
        }
        // Connection to the selected server is now established.

        // From here on, every ShowStatus/ShowStatusW/ShowStatusId in this
        // thread will be prefixed with "[<session>] " — multi-session users
        // can tell which connection is logging "Get directory:" / etc.
        SessionContextGuard _sessionGuard(serverid);

        // Guard rolls back a fresh connection on any error path below.
        // No-op when wasconnected (existing connection must not be torn down on listing failure).
        ConnectionGuard newConnGuard(wasconnected ? nullptr : serverid,
                                     wasconnected ? nullptr : displayName.data());

        *FindData = {};

        GetServerIdAndRelativePathFromPathW(Path, remotedir.data(), remotedir.size() - 1);

        // LAN Pair: use our own directory enumeration.
        if (IsLanPairTransport(serverid)) {
            SFTP_LOG("LAN", "FsFindFirstW LAN path='%S'", Path);
            if (!serverid->lanSession || !serverid->lanSession->isConnected()) {
                SFTP_LOG("LAN", "FsFindFirstW: no active lanSession");
                SetLastError(ERROR_CONNECTION_REFUSED);
                return INVALID_HANDLE_VALUE;
            }
            const std::string remotePathUtf8 = LanRemotePathToUtf8(remotedir.data());
            SFTP_LOG("LAN", "FsFindFirstW remotePathUtf8='%s'", remotePathUtf8.c_str());
            // Root (empty or single backslash) → list available drives.
            if (remotePathUtf8.empty() || remotePathUtf8 == "\\" || remotePathUtf8 == "/") {
                std::vector<std::string> roots;
                if (!serverid->lanSession->listRoots(roots) || roots.empty()) {
                    SFTP_LOG("LAN", "FsFindFirstW: listRoots failed or empty");
                    SetLastError(ERROR_NO_MORE_FILES);
                    return INVALID_HANDLE_VALUE;
                }
                std::vector<LanPairSession::DirEntry> driveEntries;
                driveEntries.reserve(roots.size());
                for (const auto& r : roots) {
                    LanPairSession::DirEntry e;
                    e.isDir = true;
                    e.name  = r;  // e.g. "C:\\"
                    // Remove trailing backslash for display: show "C:" etc.
                    if (!e.name.empty() && e.name.back() == '\\')
                        e.name.pop_back();
                    driveEntries.push_back(std::move(e));
                }
                newConnGuard.commit();
                HANDLE hdl = LanCreateFindHandle(std::move(driveEntries), FindData, serverid);
                return hdl;
            }
            // Regular directory listing.
            std::vector<LanPairSession::DirEntry> entries;
            if (!serverid->lanSession->listDirectory(remotePathUtf8, entries)) {
                SetLastError(ERROR_PATH_NOT_FOUND);
                return INVALID_HANDLE_VALUE;
            }
            newConnGuard.commit();
            return LanCreateFindHandle(std::move(entries), FindData, serverid);
        }

        // Retrieve the directory
        SFTP_LOG("FIND", "FsFindFirstW: connection ready, calling SftpFindFirstFileW remotedir='%S'", remotedir.data());
        bool ok = (SFTP_OK == SftpFindFirstFileW(serverid, remotedir.data(), &sftpdataptr));
        SFTP_LOG("FIND", "FsFindFirstW: SftpFindFirstFileW returned ok=%d", ok ? 1 : 0);

        if (wcslen(remotedir.data()) <= 1 || wcscmp(remotedir.data() + 1, L"home") == 0) {    // root -> add ~ link to home dir
            SYSTEMTIME st;
            wcslcpy(FindData->cFileName, L"~", countof(FindData->cFileName)-1);
            GetSystemTime(&st);
            SystemTimeToFileTime(&st, &FindData->ftLastWriteTime);
            FindData->dwFileAttributes = FS_ATTR_UNIXMODE;
            FindData->dwReserved0 = LIBSSH2_SFTP_S_IFLNK | kHomeSymlinkMode;

            newConnGuard.commit();  // root listing: connection is permanent
            return CreateLastFindHandle(ok ? sftpdataptr : nullptr, serverid, false);
        }
        if (!ok) {
            if (!wasconnected) freportconnect = false;
            // newConnGuard destructor fires: SetServerIdForName(name, nullptr) → close + delete
            SetLastError(ERROR_PATH_NOT_FOUND);
            return INVALID_HANDLE_VALUE;
        }

        newConnGuard.commit();  // directory listing succeeded: connection is permanent
        if (SFTP_OK == SftpFindNextFileW(serverid, sftpdataptr, FindData)) {
            return CreateLastFindHandle(sftpdataptr, serverid, false);
        }
        SftpFindClose(serverid, sftpdataptr);
        SetLastError(ERROR_NO_MORE_FILES);
        return INVALID_HANDLE_VALUE;
    });
}

HANDLE WINAPI FsFindFirst(LPCSTR Path, LPWIN32_FIND_DATA FindData)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, INVALID_HANDLE_VALUE, [&]() -> HANDLE {
        WIN32_FIND_DATAW FindDataW;
        std::array<WCHAR, wdirtypemax> pathW{};
        HANDLE retval = FsFindFirstW(awlcopy(pathW.data(), Path, pathW.size() - 1), &FindDataW);
        if (retval != INVALID_HANDLE_VALUE)
            copyfinddatawa(FindData, &FindDataW);
        return retval;
    });
}

BOOL WINAPI FsFindNextW(HANDLE Hdl, LPWIN32_FIND_DATAW FindData)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FALSE, [&]() -> BOOL {
        pLastFindStuct lf;
        std::array<char, wdirtypemax> name{};

        // Root enumeration sentinel used by FsFindFirstW for helper pseudo-entry.
        if (Hdl == kFsFindRootSentinel)
            return false;

        lf = (pLastFindStuct)Hdl;
        if (!lf || lf == INVALID_HANDLE_VALUE)
            return false;

        if (lf->rootfindfirst) {
            name[0] = 0;
            SERVERHANDLE hdl = FindFirstServer(name.data(), name.size() - 1);
            if (!hdl)
                return false;
            awlcopy(FindData->cFileName, name.data(), countof(FindData->cFileName)-1);
            lf->rootfindhandle = hdl;
            lf->rootfindfirst = false;
            SetInt64ToFileTime(&FindData->ftLastWriteTime, FS_TIME_UNKNOWN);
            FindData->dwFileAttributes = FS_ATTR_UNIXMODE;
            FindData->dwReserved0 = LIBSSH2_SFTP_S_IFLNK; // Link entry.
            FindData->nFileSizeLow = 0;
            return true;
        }
        if (lf->rootfindhandle) {
            name[0] = 0;
            lf->rootfindhandle = FindNextServer(lf->rootfindhandle, name.data(), name.size() - 1);
            if (!lf->rootfindhandle)
                return false;
            awlcopy(FindData->cFileName, name.data(), countof(FindData->cFileName)-1);
            FindData->dwFileAttributes = FS_ATTR_UNIXMODE;
            FindData->dwReserved0 = LIBSSH2_SFTP_S_IFLNK; // Link entry.
            return true;
        }
        if (lf->isPluginFolder) {
            auto* state = static_cast<PluginFolderFindState*>(lf->sftpdataptr);
            if (!state || state->index >= state->entries.size())
                return false;
            FillFindDataFromPluginEntry(*FindData, state->entries[state->index++]);
            return true;
        }
        if (lf->isLanPair) {
            auto* state = static_cast<LanPairFindState*>(lf->sftpdataptr);
            if (!state || state->index >= state->entries.size())
                return false;
            LanFillFindData(FindData, state->entries[state->index++]);
            return true;
        }
        if (lf->sftpdataptr) {
            int rc = SftpFindNextFileW(lf->serverid, lf->sftpdataptr, FindData);
            return (rc == SFTP_OK) ? true : false;
        }
        return false;
    });
}

BOOL WINAPI FsFindNext(HANDLE Hdl, LPWIN32_FIND_DATA FindData)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FALSE, [&]() -> BOOL {
        WIN32_FIND_DATAW FindDataW;
        copyfinddataaw(&FindDataW, FindData);
        BOOL retval = FsFindNextW(Hdl, &FindDataW);
        if (retval)
            copyfinddatawa(FindData, &FindDataW);
        return retval;
    });
}

int WINAPI FsFindClose(HANDLE Hdl)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, 0, [&]() -> int {
        if (!Hdl || Hdl == INVALID_HANDLE_VALUE)
            return 0;
        pLastFindStuct lf = (pLastFindStuct)Hdl;
        if (lf->isPluginFolder) {
            delete static_cast<PluginFolderFindState*>(lf->sftpdataptr);
            lf->sftpdataptr = nullptr;
        } else if (lf->isLanPair) {
            delete static_cast<LanPairFindState*>(lf->sftpdataptr);
            lf->sftpdataptr = nullptr;
        } else if (lf->sftpdataptr) {
            SftpFindClose(lf->serverid, lf->sftpdataptr);
            lf->sftpdataptr = nullptr;
        }
        if (lf->rootfindhandle) {
            FindCloseServer(lf->rootfindhandle);
            lf->rootfindhandle = nullptr;
        }
        delete lf;
        return 0;
    });
}

BOOL WINAPI FsMkDirW(LPCWSTR Path)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FALSE, [&]() -> BOOL {
        const std::wstring_view pathView = Path ? std::wstring_view(Path) : std::wstring_view{};
        if (pathView.size() < 2)
            return false;

        // Folder-aware routing: classify the path via the resolver.
        // SessionWithSubpath → real server-side mkdir on the remote.
        // SessionLeaf / Folder → name collision, refuse.
        // Invalid → treat as "new session under the current namespace position",
        // letting the (possibly slash-separated) DisplayName carry the folder
        // prefix automatically.
        const PathResolution r = ResolvePathKindW(Path);

        if (r.kind == PathKind::SessionWithSubpath) {
            // Use std::wstring instead of std::array<WCHAR, wdirtypemax>
            std::wstring remotedir(wdirtypemax, L'\0');
            pConnectSettings serverid = GetServerIdAndRelativePathFromPathW(Path, remotedir.data(), remotedir.size() - 1);
            remotedir.resize(wcslen(remotedir.data()));
            if (!serverid)
                return false;
            SessionContextGuard _sessionGuard(serverid);
            if (IsLanPairTransport(serverid)) {
                if (!serverid->lanSession || !serverid->lanSession->isConnected()) return false;
                return serverid->lanSession->mkdir(LanRemotePathToUtf8(remotedir.data()));
            }
            // PHP Agent TAR mode: skip remote mkdir; directories are created by TAR extraction.
            // Also start TAR session here if not already active (e.g. single-directory copy).
            if (IsPhpAgentTransport(serverid) && serverid->php_tar) {
                SFTP_LOG("TAR", "FsMkDirW TAR: dir='%S' tarWasActive=%d",
                         remotedir.data(), TarUploadSessionIsActive(serverid) ? 1 : 0);
                if (!TarUploadSessionIsActive(serverid))
                    TarUploadSessionBegin(serverid);
                return true;
            }
            int rc = SftpCreateDirectoryW(serverid, remotedir.data());
            return (rc == SFTP_OK) ? true : false;
        }

        if (r.kind == PathKind::SessionLeaf || r.kind == PathKind::Folder) {
            // A saved session or a folder grouping already occupies that name.
            return false;
        }

        // Invalid → would normally mean "F7 to create a new saved session",
        // but TC also calls FsMkDir when it auto-creates a destination folder
        // during a multi-operation copy/move. Two heuristics catch this:
        //
        // 1. g_inMultiOpTransfer is set by FsStatusInfo for RENMOV_MULTI —
        //    catches every FsMkDir after TC has fired the status callback
        //    (typically the nested ones, after the top-level destination).
        //
        // 2. g_lastFailedFindPath is set by FsFindFirstW when the resolver
        //    can't locate the path — catches the very first FsMkDir in a
        //    paste flow, where TC does "FsFindFirst (does it exist?) →
        //    FsMkDir (no? create it)" and the status callback hasn't fired
        //    yet for the first leg.
        //
        // Either signal → folder is implicit, just acknowledge and let the
        // following FsRenMovFile calls materialise it via slash-prefixed
        // session DisplayNames.
        if (g_inMultiOpTransfer)
            return true;
        if (!g_lastFailedFindPath.empty() &&
            _wcsicmp(g_lastFailedFindPath.c_str(), Path) == 0) {
            g_lastFailedFindPath.clear();  // consume so it doesn't leak forward
            return true;
        }

        // Invalid → create a new saved session. The target DisplayName is the
        // full path-derived string (with '/' joining folder prefix + leaf),
        // so the same code path handles "F7 in the plugin root" and "F7
        // inside any folder" uniformly.
        const std::string newDisplay = PathToDisplayNameW(Path);
        if (newDisplay.empty())
            return false;

        // Capture TC main window before opening any modal dialog (GetActiveWindow is valid here)
        HWND hTcPanel = GetActiveWindow();
        HWND hTcMain  = hTcPanel ? GetAncestor(hTcPanel, GA_ROOTOWNER) : nullptr;
        if (!hTcMain)
            hTcMain = FindWindowA("TTOTAL_CMD", nullptr);

        // User pressed F7 on the [F7 = new connection] / Quick Connection
        // helper entries and accepted the autofilled name → open the quick
        // connect dialog instead of creating a literally-named session.
        if (_stricmp(newDisplay.c_str(), s_quickconnect) == 0 ||
            _stricmp(newDisplay.c_str(), s_f7newconnection) == 0) {
            SftpConnectToServer(s_quickconnect, inifilename, nullptr);
            LoadServersFromIniW(inifilenameW, s_quickconnect);
            if (hTcMain) PostMessage(hTcMain, WM_USER + 51, 540, 0);
            return true;
        }

        // Normal new named connection
        if (SftpConfigureServer(newDisplay.c_str(), inifilename)) {
            LoadServersFromIniW(inifilenameW, s_quickconnect);
            if (hTcMain) PostMessage(hTcMain, WM_USER + 51, 540, 0);
            return true;
        }
        return false;
    });
}

BOOL WINAPI FsMkDir(LPCSTR Path)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FALSE, [&]() -> BOOL {
        if (!Path || !Path[0])
            return false;
        std::array<WCHAR, wdirtypemax> wbuf{};
        return FsMkDirW(awlcopy(wbuf.data(), Path, wbuf.size() - 1));
    });
}
