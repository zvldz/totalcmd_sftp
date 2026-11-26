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
#include "ConnectionDialog.h"
#include "ProfileSettings.h"
#include "DllExceptionBarrier.h"
#if SFTP_EXTRA
#include "LanPairSession.h"
#endif
#include "PluginEntryPointsInternal.h"
#include "ImportSourceRegistry.h"
#include "ImportCache.h"
#include "VirtualSessionRegistry.h"
#include <mutex>
#include "ProfileSettings.h"

// Path of the most recent FsFindFirstW call that returned PATH_NOT_FOUND.
// TC's "paste into a non-existent folder" flow does FsFindFirstW (to check
// existence) → fails → FsMkDir (create the folder) for the same path. By
// remembering that exact path, FsMkDir can recognise the second leg of the
// pattern and skip the new-session dialog, even when TC has not yet fired
// its RENMOV_MULTI status callback (which sometimes comes AFTER the first
// FsMkDir). On user-initiated F7 the previous failed-find path is empty or
// stale (TC didn't pre-check), so the dialog still opens normally.
// Per thread: the failed lookup and the FsMkDir that follows it come
// from the same thread.
static thread_local std::wstring g_lastFailedFindPath;

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

#if SFTP_EXTRA
struct LanPairFindState {
    std::vector<LanPairSession::DirEntry> entries;
    size_t index = 0;
};
#endif

// Plugin-side namespace entry: a saved session, a folder grouping saved
// sessions, the [F7 = new connection] pseudo-helper, or — inside the
// [Active Sessions] magic folder — a live session row / bulk-disconnect
// trigger. Used to render the listing for the plugin root and any folder
// under it.
struct PluginFolderEntry {
    std::string name;
    enum class Kind {
        Folder,           // grouping of saved sessions (FILE_ATTRIBUTE_DIRECTORY)
        Session,          // saved session leaf (IFLNK + UNIXMODE → padlock icon)
        Pseudo,           // [F7 = new connection] help entry
        ActiveSession,    // live session row inside [Active Sessions] (plain file)
        ActiveBulkOp,     // [Disconnect All] inside [Active Sessions] (plain file)
        ImportsUmbrella,  // [Imports] in the plugin root (directory)
        ImportSource,     // [SecureCRT] etc. inside [Imports] (directory)
        ImportSession,    // cached virtual session inside a source (plain file)
        ImportPseudo,     // [Refresh]/[Add custom...]/[Manage custom locations]
        ProxiesUmbrella,  // [Proxies] in the plugin root (directory)
        ProxyRecord       // one proxy record inside [Proxies] (plain file)
    } kind = Kind::Session;
    DWORD       helpFileSize   = 0;      // Pseudo only — used as nFileSizeLow.
    bool        pseudoAsFolder = false;  // ImportPseudo only — true for [Manage
                                         // custom locations] (Enter navigates
                                         // into a subfolder); false for
                                         // [Refresh]/[Add custom...] (Enter
                                         // triggers an action).
};

struct PluginFolderFindState {
    std::vector<PluginFolderEntry> entries;
    size_t index = 0;
};

typedef struct {
    LPVOID           sftpdataptr;    /* LIBSSH2_SFTP_HANDLE, SCP_DATA, LanPairFindState*, or PluginFolderFindState* */
    pConnectSettings serverid;
    bool             isLanPair;       /* if true, sftpdataptr is LanPairFindState* */
    bool             isPluginFolder;  /* if true, sftpdataptr is PluginFolderFindState* */
} tLastFindStuct, *pLastFindStuct;

static HANDLE CreateLastFindHandle(LPVOID sftpdataptr, pConnectSettings serverid) noexcept
{
    auto lfMem = std::make_unique<tLastFindStuct>();
    lfMem->sftpdataptr = sftpdataptr;
    lfMem->serverid = serverid;
    lfMem->isLanPair = false;
    lfMem->isPluginFolder = false;
    return static_cast<HANDLE>(lfMem.release());
}

// ---------------------------------------------------------------------------
// LAN Pair helpers for directory enumeration (extra build only)
// ---------------------------------------------------------------------------
#if SFTP_EXTRA

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
#endif // SFTP_EXTRA

// ---------------------------------------------------------------------------
// Plugin-side folder enumeration
// ---------------------------------------------------------------------------

namespace {

struct CaseInsensitiveLess {
    bool operator()(const std::string& a, const std::string& b) const noexcept {
        return _stricmp(a.c_str(), b.c_str()) < 0;
    }
};

// Working buffers shared by every "listing a directory of session paths"
// pass: `subfolders` receives Folder entries, `sessions` receives leaf
// entries; `foldersSeen` deduplicates folder heads across the input stream.
// The plugin-root and Imports-source listings both hydrate one of these
// and finalise it identically.
struct DedupBuckets {
    std::set<std::string, CaseInsensitiveLess> foldersSeen;
    std::vector<PluginFolderEntry>             subfolders;
    std::vector<PluginFolderEntry>             sessions;
};

// Given one path relative to the listing root (e.g. "team/aws/prod-web1"),
// route into either a Folder head (first segment before '/') or a session
// leaf (no '/'). Session leaves carry `sessionKind`; adapters use
// ImportSession, the plugin root uses Session.
//
// `sessionsSeen`, when non-null, deduplicates session names across calls —
// used by the Imports listing where the same displayName can appear in more
// than one channel. Plugin root passes nullptr (session names are unique in
// the underlying registry already).
void ClassifyRelativeEntry(DedupBuckets&                       buckets,
                            std::string                         relative,
                            PluginFolderEntry::Kind             sessionKind,
                            std::set<std::string, CaseInsensitiveLess>* sessionsSeen)
{
    const size_t slashPos = relative.find('/');
    if (slashPos == std::string::npos) {
        if (sessionsSeen && !sessionsSeen->insert(relative).second)
            return;
        PluginFolderEntry e;
        e.name = std::move(relative);
        e.kind = sessionKind;
        buckets.sessions.push_back(std::move(e));
        return;
    }
    std::string sub = relative.substr(0, slashPos);
    if (buckets.foldersSeen.insert(sub).second) {
        PluginFolderEntry e;
        e.name = std::move(sub);
        e.kind = PluginFolderEntry::Kind::Folder;
        buckets.subfolders.push_back(std::move(e));
    }
}

// Folder wins on a name collision; then move subfolders + sessions into
// `outEntries` in TC's convention order (folders first, leaves last).
void EmitDedupBuckets(DedupBuckets&                     buckets,
                      std::vector<PluginFolderEntry>&   outEntries)
{
    buckets.sessions.erase(std::remove_if(buckets.sessions.begin(),
                                           buckets.sessions.end(),
        [&](const PluginFolderEntry& s) { return buckets.foldersSeen.contains(s.name); }),
        buckets.sessions.end());
    for (auto& e : buckets.subfolders) outEntries.push_back(std::move(e));
    for (auto& e : buckets.sessions)   outEntries.push_back(std::move(e));
}

}  // anonymous namespace

// Fill a WIN32_FIND_DATAW from one PluginFolderEntry. Pseudo entries show the
// length of the IDS_HELPTEXT string (ANSI, up to 255 bytes); folder entries
// carry FILE_ATTRIBUTE_DIRECTORY; saved sessions are shown as IFLNK entries,
// which is what F8 (delete) and Enter (open) on a session rely on.
static void FillFindDataFromPluginEntry(WIN32_FIND_DATAW& fd, const PluginFolderEntry& e)
{
    fd = {};
    iwlcopy(fd.cFileName, e.name.c_str(), countof(fd.cFileName) - 1);
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
        case PluginFolderEntry::Kind::ImportsUmbrella:
        case PluginFolderEntry::Kind::ImportSource:
            // Directories: user navigates into them like any TC folder.
            fd.dwFileAttributes = FILE_ATTRIBUTE_DIRECTORY;
            break;
        case PluginFolderEntry::Kind::ImportSession:
            // Plain file so Enter routes through FsExecuteFile "open" (where
            // the virtual-session connect branch lives). F5 (copy) triggers
            // materialise in FsRenMovFile.
            fd.dwFileAttributes = FILE_ATTRIBUTE_NORMAL;
            break;
        case PluginFolderEntry::Kind::ProxiesUmbrella:
            fd.dwFileAttributes = FILE_ATTRIBUTE_DIRECTORY;
            break;
        case PluginFolderEntry::Kind::ProxyRecord:
            // Plain file: Enter reaches FsExecuteFile, where the record's
            // editor opens, and F8 reaches FsDeleteFileW to remove it.
            fd.dwFileAttributes = FILE_ATTRIBUTE_NORMAL;
            break;
        case PluginFolderEntry::Kind::ImportPseudo:
            // pseudoAsFolder=true → [Manage custom locations] (a real
            // sub-listing lives inside). pseudoAsFolder=false → [Refresh]
            // or [Add custom location...] (Enter triggers an action; TC
            // treats the row as a file and calls FsExecuteFile).
            // Plain attributes — no FILE_ATTRIBUTE_SYSTEM. TC appears to
            // short-circuit its icon pipeline for system-flagged entries
            // and paint its own warning glyph regardless of what our
            // FsExtractCustomIcon returns, so the SYSTEM tag hid the
            // stock-icon path. Visual distinction is provided by the
            // custom icon returned in FsExtractCustomIcon.
            fd.dwFileAttributes = e.pseudoAsFolder
                ? FILE_ATTRIBUTE_DIRECTORY
                : FILE_ATTRIBUTE_NORMAL;
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

    DedupBuckets buckets;
    bool hasActiveSession = false;
    {
        std::array<char, wdirtypemax> nameBuf{};
        SERVERHANDLE hdl = FindFirstServer(nameBuf.data(), nameBuf.size() - 1);
        while (hdl) {
            std::string fullName = nameBuf.data();
            // Skip virtual (Imports-cache-backed) sessions. When the user
            // opens one from inside [Imports], we register it in the server
            // registry under a TC-safe alias (`__vimp_<sourceId>_<hash>`).
            // The alias must still count towards hasActiveSession so
            // [Active Sessions] can list it for the disconnect gesture, but
            // must not appear as a fake session row in the plugin root
            // listing.
            const bool isVirtual = sftp::IsVirtualSessionAlias(fullName.c_str());
            // Track whether any session is currently connected — used at root
            // to decide whether to surface the [Active Sessions] magic folder.
            if (isRoot && !hasActiveSession &&
                GetServerIdFromName(fullName.c_str(), GetCurrentThreadId()) != nullptr) {
                hasActiveSession = true;
            }
            if (isVirtual) {
                nameBuf[0] = 0;
                hdl = FindNextServer(hdl, nameBuf.data(), nameBuf.size() - 1);
                continue;
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
                ClassifyRelativeEntry(buckets, std::move(relative),
                    PluginFolderEntry::Kind::Session, nullptr);
            }
            nameBuf[0] = 0;
            hdl = FindNextServer(hdl, nameBuf.data(), nameBuf.size() - 1);
        }
    }

    // At root, if anything is currently connected, expose the magic
    // [Active Sessions] folder right after the F7 helper entry so the user
    // can see and disconnect open sessions without tab-juggling.
    if (isRoot && hasActiveSession) {
        PluginFolderEntry active;
        active.name = MagicDisplayName(kActiveSessionsFolder);
        active.kind = PluginFolderEntry::Kind::Folder;
        state->entries.push_back(std::move(active));
    }

    // At root, always expose the umbrella [Imports] folder that groups every
    // known session-import source. Detection state of individual sources
    // does not gate this — the umbrella itself is unconditional so the user
    // can always reach [Add custom location...] for a source whose program
    // is not currently installed.
    if (isRoot) {
        PluginFolderEntry imports;
        imports.name = MagicDisplayName(kImportsFolder);
        imports.kind = PluginFolderEntry::Kind::ImportsUmbrella;
        state->entries.push_back(std::move(imports));
    }

    // At root, always expose [Proxies]. Unconditional for the same reason the
    // imports umbrella is: an empty list is where the first record gets made,
    // and a folder that appears only once a record exists offers nowhere to
    // make one.
    if (isRoot) {
        PluginFolderEntry proxies;
        proxies.name = MagicDisplayName(kProxiesFolder);
        proxies.kind = PluginFolderEntry::Kind::ProxiesUmbrella;
        state->entries.push_back(std::move(proxies));
    }

    EmitDedupBuckets(buckets, state->entries);

    auto lf = std::make_unique<tLastFindStuct>();
    lf->sftpdataptr    = state.release();
    lf->serverid       = nullptr;
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
namespace {
std::string ActiveSessionLabel(const std::string& registryName);
}

static HANDLE BuildActiveSessionsListing(WIN32_FIND_DATAW* FindData)
{
    auto state = std::make_unique<PluginFolderFindState>();

    // Active sessions first; [Disconnect All] only appears when at least one
    // session is connected (an empty listing after F8 simply leaves the user
    // with TC's `..` parent entry to back out). A session from [Imports] is
    // listed under its source and its name there; IsActiveSessionsPath turns
    // that label back into the session.
    std::array<char, wdirtypemax> nameBuf{};
    SERVERHANDLE hdl = FindFirstServer(nameBuf.data(), nameBuf.size() - 1);
    while (hdl) {
        if (GetServerIdFromName(nameBuf.data(), GetCurrentThreadId()) != nullptr) {
            PluginFolderEntry e;
            e.name = ActiveSessionLabel(nameBuf.data());
            e.kind = PluginFolderEntry::Kind::ActiveSession;
            state->entries.push_back(std::move(e));
        }
        nameBuf[0] = 0;
        hdl = FindNextServer(hdl, nameBuf.data(), nameBuf.size() - 1);
    }
    if (!state->entries.empty()) {
        PluginFolderEntry bulk;
        bulk.name = MagicDisplayName(kDisconnectAllEntry);
        bulk.kind = PluginFolderEntry::Kind::ActiveBulkOp;
        state->entries.insert(state->entries.begin(), std::move(bulk));
    }

    auto lf = std::make_unique<tLastFindStuct>();
    lf->sftpdataptr    = state.release();
    lf->serverid       = nullptr;
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

// Build the listing shown inside [Imports]\<Source>\ (source root or any
// nested folder under it). At the source root the listing is prepended with
// pseudo entries: an optional "not detected" hint, [Refresh], [Add custom
// location...], and [Manage custom locations] when at least one custom path
// is persisted for this source. Below that come the cache-driven sessions
// from ImportCache filtered by subPath, with sub-folder de-duplication
// mirroring BuildPluginFolderListing.
static HANDLE BuildImportsSourceListing(const std::string& sourceId,
                                         const std::string& subPath,
                                         WIN32_FIND_DATAW* FindData)
{
    auto state = std::make_unique<PluginFolderFindState>();
    sftp::IExternalSessionSource* adapter =
        sftp::GetImportSourceRegistry().Find(sourceId.c_str());

    const bool isManageView = (subPath == kManageCustomFolder);
    const bool atSourceRoot = subPath.empty();

    // A source that can tell when it changed is re-scanned on the visit
    // after a change, so its edits show without [Refresh] — the standard
    // location and every path the user added. The first visit in a session
    // always scans once: the files may have changed while Total Commander
    // was closed. A path that has gone missing re-scans as Unreachable,
    // which keeps its sessions in the cache.
    if (atSourceRoot && adapter) {
        static std::unordered_map<std::string, std::string> s_lastStamp;
        static std::mutex s_lastStampMutex;
        std::string stamp = adapter->ChangeStamp();
        for (const auto& path : LoadImportCustomPaths(sourceId.c_str(), inifilename))
            stamp += adapter->CustomPathStamp(unicode_util::internal_to_utf8(path));
        if (!stamp.empty()) {
            bool changed = false;
            {
                std::lock_guard<std::mutex> lock(s_lastStampMutex);
                const auto it = s_lastStamp.find(sourceId);
                changed = it == s_lastStamp.end() || it->second != stamp;
                if (changed)
                    s_lastStamp[sourceId] = stamp;
            }
            if (changed) {
                SFTP_LOG("IMPORT", "%s changed on disk, re-scanning", sourceId.c_str());
                RefreshImportSource(sourceId);
            }
        }
    }

    if (atSourceRoot) {
        // Detection hint — shown only when the standard location is not
        // currently reachable. The hint is a plain-file pseudo so Enter does
        // nothing; F8 also does nothing (delete guard blocks pseudos).
        if (adapter && !adapter->DetectStandard()) {
            PluginFolderEntry hint;
            std::string text = unicode_util::utf8_to_internal(
                LngStrU8(IDS_MAGIC_NOT_DETECTED, "%s not currently detected"));
            const size_t at = text.find("%s");
            if (at == std::string::npos)
                text = std::string(adapter->FolderName()) + " " + text;
            else
                text.replace(at, 2, adapter->FolderName());
            hint.name = text;
            hint.kind = PluginFolderEntry::Kind::ImportPseudo;
            hint.pseudoAsFolder = false;
            state->entries.push_back(std::move(hint));
        }

        PluginFolderEntry refresh;
        refresh.name = MagicDisplayName(kRefreshEntry);
        refresh.kind = PluginFolderEntry::Kind::ImportPseudo;
        refresh.pseudoAsFolder = false;
        state->entries.push_back(std::move(refresh));

        // [Add custom location...] appears only when the adapter has a
        // custom-path concept at all (Folder or File). A registry-only or
        // similarly locked source returns None and gets no entry.
        const bool hasCustomPicker = adapter &&
            adapter->CustomPathPicker() != sftp::CustomPathPickerKind::None;
        if (hasCustomPicker) {
            PluginFolderEntry addCustom;
            addCustom.name = MagicDisplayName(kAddCustomEntry);
            addCustom.kind = PluginFolderEntry::Kind::ImportPseudo;
            addCustom.pseudoAsFolder = false;
            state->entries.push_back(std::move(addCustom));
        }

        // [Manage custom locations] appears only when the user has
        // configured at least one custom path for this source. Reading the
        // list here is cheap (single IniGetString) and TC calls
        // this once per FsFindFirst.
        const auto customPaths = hasCustomPicker
            ? LoadImportCustomPaths(sourceId.c_str(), inifilename)
            : std::vector<std::string>{};
        if (!customPaths.empty()) {
            PluginFolderEntry manage;
            manage.name = MagicDisplayName(kManageCustomFolder);
            manage.kind = PluginFolderEntry::Kind::ImportPseudo;
            manage.pseudoAsFolder = true;   // sub-folder — Enter navigates in
            state->entries.push_back(std::move(manage));
        }
    }

    // [Manage custom locations]\ sub-view: list the persisted custom paths
    // as plain-file entries. F8 on a row removes that path (dispatched in
    // FsDeleteFileW with a positive-match branch for this sub-view).
    //
    // Display trick: TC treats `\` in an entry name as a path separator and
    // only renders the trailing leaf, which for absolute Windows paths like
    // `C:\Users\<name>\...\Sessions` shows just `Sessions` — useless. We
    // replace `\` with `/` for display (matching our internal path
    // normalisation everywhere else). The F8-remove handler in
    // FsDeleteFileW reverses the substitution before hitting the INI, so
    // the persisted path stays in canonical Windows form.
    if (isManageView) {
        const auto customPaths = LoadImportCustomPaths(sourceId.c_str(), inifilename);
        for (const auto& p : customPaths) {
            PluginFolderEntry e;
            e.name = p;
            std::replace(e.name.begin(), e.name.end(), '\\', '/');
            e.kind = PluginFolderEntry::Kind::ImportPseudo;
            e.pseudoAsFolder = false;
            state->entries.push_back(std::move(e));
        }
    }

    // Cache-driven listing. Skipped when we are inside the [Manage custom
    // locations] view (that's handled by the block above). Uses the same
    // classify/emit helpers as BuildPluginFolderListing — the only Imports-
    // specific detail is that the same displayName can appear in more than
    // one channel, so session names get an extra dedup set.
    if (!isManageView) {
        DedupBuckets buckets;
        std::set<std::string, CaseInsensitiveLess> sessionsSeen;

        const auto cached = sftp::GetImportCache().ListSource(sourceId);
        for (const auto& s : cached) {
            std::string relative;
            if (atSourceRoot) {
                relative = s.displayName;
            } else {
                const std::string needle = subPath + "/";
                if (s.displayName.size() > needle.size() &&
                    _strnicmp(s.displayName.c_str(), needle.c_str(), needle.size()) == 0)
                {
                    relative = s.displayName.substr(needle.size());
                } else {
                    continue;
                }
            }
            ClassifyRelativeEntry(buckets, std::move(relative),
                PluginFolderEntry::Kind::ImportSession, &sessionsSeen);
        }

        EmitDedupBuckets(buckets, state->entries);
    }

    auto lf = std::make_unique<tLastFindStuct>();
    lf->sftpdataptr    = state.release();
    lf->serverid       = nullptr;
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

// Build the top-level [Imports]\ listing. One directory entry per registered
// adapter, no detection-state suffix (the "not detected" hint appears inside
// each source folder — see BuildImportsSourceListing when it lands).
static HANDLE BuildImportsUmbrellaListing(WIN32_FIND_DATAW* FindData)
{
    auto state = std::make_unique<PluginFolderFindState>();

    for (const auto& adapter : sftp::GetImportSourceRegistry().Adapters()) {
        PluginFolderEntry e;
        e.name = adapter->FolderName();
        e.kind = PluginFolderEntry::Kind::ImportSource;
        state->entries.push_back(std::move(e));
    }

    auto lf = std::make_unique<tLastFindStuct>();
    lf->sftpdataptr    = state.release();
    lf->serverid       = nullptr;
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

namespace {

// The magic folders and pseudo entries: the English name, which the code
// works with, and the string shown in its place. The folders of the plugin
// root are also recognised under every shipped translation, so a path saved
// in one language still leads there after a switch; no session name can
// take one, as session names cannot start with '['. The entries inside
// folders sit beside imported sessions, whose names can, so they are
// recognised in English and in the language in use only.
struct MagicName {
    const char* identity;
    UINT        resId;
    bool        everyLanguage;
};

constexpr MagicName kMagicNames[] = {
    { kImportsFolder,        IDS_MAGIC_IMPORTS,         true  },
    { kActiveSessionsFolder, IDS_MAGIC_ACTIVE_SESSIONS, true  },
    { kProxiesFolder,        IDS_MAGIC_PROXIES,         true  },
    { kDisconnectAllEntry,   IDS_MAGIC_DISCONNECT_ALL,  false },
    { kRefreshEntry,         IDS_MAGIC_REFRESH,         false },
    { kAddCustomEntry,       IDS_MAGIC_ADD_CUSTOM,      false },
    { kManageCustomFolder,   IDS_MAGIC_MANAGE_CUSTOM,   false },
};

const MagicName* FindMagicName(const char* identity)
{
    for (const MagicName& m : kMagicNames)
        if (strcmp(m.identity, identity) == 0)
            return &m;
    return nullptr;
}

// A translation is taken only in the shape every one must have: in square
// brackets, and a valid file name.
bool HasMagicShape(std::string_view s)
{
    if (s.size() < 3 || s.front() != '[' || s.back() != ']')
        return false;
    for (const char c : s)
        if (static_cast<unsigned char>(c) < 0x20 || strchr("\\/:*?\"<>|", c))
            return false;
    return true;
}

std::string ShownMagicName(const MagicName& m)
{
    const std::string shown = unicode_util::utf8_to_internal(LngStrU8(m.resId, m.identity));
    return HasMagicShape(shown) ? shown : std::string(m.identity);
}

bool SameNameW(std::wstring_view a, std::wstring_view b)
{
    return a.size() == b.size() &&
           CompareStringOrdinal(a.data(), static_cast<int>(a.size()),
                                b.data(), static_cast<int>(b.size()), TRUE) == CSTR_EQUAL;
}

// Whether `segment` (one path component) names `m`.
bool NamesMagic(std::wstring_view segment, const MagicName& m)
{
    if (SameNameW(segment, unicode_util::internal_to_wide(m.identity)) ||
        SameNameW(segment, unicode_util::internal_to_wide(ShownMagicName(m))))
        return true;
    if (m.everyLanguage) {
        for (const std::string& t : LngAllTranslations(m.resId, hinst))
            if (HasMagicShape(t) && SameNameW(segment, unicode_util::internal_to_wide(unicode_util::utf8_to_internal(t))))
                return true;
    }
    return false;
}

// The first component of `view`, up to a '\' or '/'.
std::wstring_view FirstSegment(std::wstring_view view)
{
    return view.substr(0, view.find_first_of(L"\\/"));
}

// `entry` (folders joined by '/') with a first component that names one of
// `pseudo` (the entries of that folder) put back to its English name.
void CanonicalisePseudoEntry(std::string& entry, std::initializer_list<const char*> pseudo)
{
    const size_t slash = entry.find('/');
    const std::wstring first = unicode_util::internal_to_wide(entry.substr(0, slash));
    for (const char* identity : pseudo) {
        const MagicName* m = FindMagicName(identity);
        if (!m || !NamesMagic(first, *m))
            continue;
        entry = std::string(m->identity) + (slash == std::string::npos ? std::string() : entry.substr(slash));
        return;
    }
}

}  // namespace

std::string MagicDisplayName(const char* identity)
{
    const MagicName* m = FindMagicName(identity);
    return m ? ShownMagicName(*m) : std::string(identity);
}

// Shared body of the magic-folder path classifiers: they differ only in
// which folder they match.
static bool IsMagicFolderPath(LPCWSTR path, const char* identity, std::string* outEntry,
                              std::initializer_list<const char*> pseudo)
{
    if (!path || path[0] != L'\\') return false;
    const std::wstring_view view(path + 1);  // strip leading '\\'
    const MagicName* magic = FindMagicName(identity);
    const std::wstring_view segment = FirstSegment(view);
    if (!magic || !NamesMagic(segment, *magic)) return false;
    const std::wstring_view after = view.substr(segment.size());
    if (after.empty() || (after.size() == 1 && (after[0] == L'\\' || after[0] == L'/'))) {
        if (outEntry) outEntry->clear();
        return true;
    }
    if (outEntry) {
        std::wstring_view trail = after.substr(1);
        // Internal string with any '\' replaced by '/' so folder-nested
        // DisplayNames round-trip cleanly.
        *outEntry = unicode_util::wide_to_internal(trail);
        std::replace(outEntry->begin(), outEntry->end(), '\\', '/');
        CanonicalisePseudoEntry(*outEntry, pseudo);
    }
    return true;
}

// See PluginEntryPointsInternal.h for the contracts.
namespace {

// How an open session is named in [Active Sessions]: one from [Imports] by
// its source folder and its name there ("[SecureCRT] my/ha1"), any other by
// its own name. No saved session's name starts with '[', so the two never
// meet.
std::string ActiveSessionLabel(const std::string& registryName)
{
    if (!sftp::IsVirtualSessionAlias(registryName.c_str()))
        return registryName;
    const auto info = sftp::LookupVirtualSession(registryName);
    const auto* adapter = info ? sftp::GetImportSourceRegistry().Find(info->sourceId.c_str()) : nullptr;
    if (!adapter)
        return registryName;
    return std::string(adapter->FolderName()) + " " + info->displayName;
}

// The session an [Active Sessions] row stands for: the alias of the open
// imported session it labels, or the row name itself.
std::string ActiveSessionFromLabel(const std::string& label)
{
    if (label.empty() || label[0] != '[' || label == kDisconnectAllEntry)
        return label;
    std::array<char, wdirtypemax> nameBuf{};
    SERVERHANDLE hdl = FindFirstServer(nameBuf.data(), nameBuf.size() - 1);
    while (hdl) {
        if (sftp::IsVirtualSessionAlias(nameBuf.data()) &&
            _stricmp(ActiveSessionLabel(nameBuf.data()).c_str(), label.c_str()) == 0) {
            const std::string alias = nameBuf.data();
            FindCloseServer(hdl);
            return alias;
        }
        nameBuf[0] = 0;
        hdl = FindNextServer(hdl, nameBuf.data(), nameBuf.size() - 1);
    }
    return label;
}

}  // namespace

bool IsActiveSessionsPath(LPCWSTR path, std::string* outEntry)
{
    if (!IsMagicFolderPath(path, kActiveSessionsFolder, outEntry, { kDisconnectAllEntry }))
        return false;
    if (outEntry)
        *outEntry = ActiveSessionFromLabel(*outEntry);
    return true;
}

bool IsProxiesPath(LPCWSTR path, std::string* outEntry)
{
    return IsMagicFolderPath(path, kProxiesFolder, outEntry, {});
}

int ProxyNrFromRowName(const std::string& rowName)
{
    int nr = 0;
    size_t i = 0;
    for (; i < rowName.size() && rowName[i] >= '0' && rowName[i] <= '9'; ++i)
        nr = nr * 10 + (rowName[i] - '0');
    // A row always reads "<number>: ...", so a name without that colon after
    // its digits is some other string that merely starts with a number.
    return (i > 0 && i < rowName.size() && rowName[i] == ':') ? nr : 0;
}

// Every proxy record, one row each. A record switched off describes as empty
// and stays out, exactly as it stays out of the connection dialog's list.
static HANDLE BuildProxiesListing(WIN32_FIND_DATAW* FindData)
{
    auto state = std::make_unique<PluginFolderFindState>();
    for (const int proxynr : EnumerateProxyNumbers(inifilename)) {
        const std::wstring label = DescribeProxyRecordW(proxynr, inifilename);
        if (label.empty())
            continue;
        PluginFolderEntry e;
        e.name = unicode_util::wide_to_internal(label);
        e.kind = PluginFolderEntry::Kind::ProxyRecord;
        state->entries.push_back(std::move(e));
    }

    auto lf = std::make_unique<tLastFindStuct>();
    lf->sftpdataptr    = state.release();
    lf->serverid       = nullptr;
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

namespace {

// Internal-string copy of a wide substring, mirroring IsMagicFolderPath.
// Also normalises backslashes to '/' so nested paths round-trip cleanly
// through our path normalisation.
void WideRangeToNarrowSlash(std::wstring_view src, std::string& out)
{
    out = unicode_util::wide_to_internal(src);
    std::replace(out.begin(), out.end(), '\\', '/');
}

}  // namespace

// See PluginEntryPointsInternal.h for the contract.
ImportsPathKind ClassifyImportsPath(LPCWSTR path,
                                    std::string* outSourceId,
                                    std::string* outSubPath)
{
    if (outSourceId) outSourceId->clear();
    if (outSubPath)  outSubPath->clear();

    if (!path || path[0] != L'\\') return ImportsPathKind::NotImports;
    const std::wstring_view view(path + 1);  // strip leading '\\'
    const std::wstring_view umbrella = FirstSegment(view);
    if (!NamesMagic(umbrella, *FindMagicName(kImportsFolder)))
        return ImportsPathKind::NotImports;

    const std::wstring_view after = view.substr(umbrella.size());

    // At the umbrella itself ("\[Imports]" or "\[Imports]\").
    if (after.empty() || (after.size() == 1 && (after[0] == L'\\' || after[0] == L'/')))
        return ImportsPathKind::Umbrella;

    // Must have a separator before the source segment.
    if (after[0] != L'\\' && after[0] != L'/') return ImportsPathKind::NotImports;
    std::wstring_view rest = after.substr(1);
    if (rest.empty()) return ImportsPathKind::Umbrella;  // trailing slash consumed

    // Extract next segment — the source folder name (e.g. "[SecureCRT]").
    size_t seg_end = rest.find_first_of(L"\\/");
    const std::wstring_view segment = (seg_end == std::wstring_view::npos)
        ? rest
        : rest.substr(0, seg_end);

    // Match against every registered adapter's FolderName() (wide, case-insensitive).
    const auto& adapters = sftp::GetImportSourceRegistry().Adapters();
    for (const auto& adapter : adapters) {
        const std::wstring fname = unicode_util::internal_to_wide(adapter->FolderName());
        if (fname.size() != segment.size()) continue;
        if (_wcsnicmp(fname.data(), segment.data(), fname.size()) != 0) continue;

        if (outSourceId) *outSourceId = adapter->SourceId();

        if (seg_end == std::wstring_view::npos)
            return ImportsPathKind::SourceRoot;

        const std::wstring_view trail = rest.substr(seg_end + 1);
        if (trail.empty())
            return ImportsPathKind::SourceRoot;  // "\[Imports]\<Source>\" trailing slash
        if (outSubPath) {
            WideRangeToNarrowSlash(trail, *outSubPath);
            CanonicalisePseudoEntry(*outSubPath, { kRefreshEntry, kAddCustomEntry, kManageCustomFolder });
        }
        return ImportsPathKind::SourceSubPath;
    }

    // Second segment did not match any registered adapter. Surface the
    // unrecognised segment (plus any trailing path) so callers can log it.
    if (outSubPath) WideRangeToNarrowSlash(rest, *outSubPath);
    return ImportsPathKind::UnknownSource;
}

// See PluginEntryPointsInternal.h for the contract.
bool ImportedSessionToAliasPathW(LPCWSTR path, bool leafToo, std::wstring& out)
{
    std::string sourceId, subPath;
    if (ClassifyImportsPath(path, &sourceId, &subPath) != ImportsPathKind::SourceSubPath)
        return false;
    while (!subPath.empty() && subPath.back() == '/')
        subPath.pop_back();

    // The longest leading part that names a cached session is the session;
    // what follows it is the path on the server, as for a saved session in
    // a folder.
    std::string session = subPath;
    std::string section;
    while (!session.empty()) {
        section = sftp::GetImportCache().SectionNameForConnect(sourceId, session);
        if (!section.empty())
            break;
        const size_t slash = session.find_last_of('/');
        if (slash == std::string::npos)
            return false;
        session.resize(slash);
    }
    if (section.empty())
        return false;

    std::string remote = subPath.substr(session.size());
    if (remote.empty() && !leafToo)
        return false;
    std::replace(remote.begin(), remote.end(), '/', '\\');

    const std::string alias = sftp::MakeVirtualSessionAlias(sourceId, section);
    sftp::RegisterVirtualSession(alias, {sourceId, section, session});

    out = L"\\";
    out += unicode_util::internal_to_wide(alias + remote);
    return true;
}

// See PluginEntryPointsInternal.h for the contract.
std::string ImportedSessionPathForAlias(const std::string& alias)
{
    if (!sftp::IsVirtualSessionAlias(alias.c_str()))
        return {};
    const auto info = sftp::LookupVirtualSession(alias);
    if (!info)
        return {};
    const auto* adapter = sftp::GetImportSourceRegistry().Find(info->sourceId.c_str());
    if (!adapter)
        return {};
    std::string out = "\\" + MagicDisplayName(kImportsFolder) + "\\" + adapter->FolderName() + "\\" + info->displayName;
    std::replace(out.begin(), out.end(), '/', '\\');
    return out;
}

// See PluginEntryPointsInternal.h for the contract.
bool AliasToImportedSessionPathW(LPCWSTR path, std::wstring& out)
{
    if (!path || path[0] != L'\\')
        return false;
    const std::wstring_view view(path + 1);
    const size_t end = view.find_first_of(L"\\/");
    const std::string alias = unicode_util::wide_to_internal(view.substr(0, end));
    const std::string shown = ImportedSessionPathForAlias(alias);
    if (shown.empty())
        return false;
    out = unicode_util::internal_to_wide(shown);
    if (end != std::wstring_view::npos)
        out += view.substr(end);
    return true;
}

HANDLE WINAPI FsFindFirstW(LPCWSTR Path, LPWIN32_FIND_DATAW FindData)
{
    sftp::DllExceptionBarrier _barrier;
    SFTP_LOG("FIND", "FsFindFirstW ENTRY path='%s'", unicode_util::wstring_to_utf8(Path ? Path : L"(null)").c_str());
    return sftp::dll_invoke(_barrier, INVALID_HANDLE_VALUE, [&]() -> HANDLE {
        std::array<WCHAR, wdirtypemax> remotedir{};
        std::array<char, wdirtypemax> displayName{};
        std::array<char, wdirtypemax> pathA{};

        // TC writes its language to wincmd.ini as soon as it is changed, so
        // every listing follows it. Background transfers list folders too;
        // they leave the translation table alone while other threads read it.
        if (IsMainThread())
            ApplyTcLanguageToPluginResources(g_wincmdIniPath);

        std::wstring aliasPath;
        UseAliasPath(Path, aliasPath, true);

        if (wcscmp(Path, L"\\") == 0) {  // in the root.
            LoadServersFromIniW(inifilenameW, s_quickconnect);
            *FindData = {};
            return BuildPluginFolderListing(std::string{}, FindData);
        }

        // [Active Sessions] magic folder — synthetic listing of currently
        // connected sessions. Detected before the resolver because the path
        // doesn't correspond to any saved session and would otherwise fall
        // through into the implicit-connect branch.
        {
            std::string proxyEntry;
            if (IsProxiesPath(Path, &proxyEntry) && proxyEntry.empty()) {
                *FindData = {};
                return BuildProxiesListing(FindData);
            }
        }

        {
            std::string trailingEntry;
            if (IsActiveSessionsPath(Path, &trailingEntry) && trailingEntry.empty()) {
                LoadServersFromIniW(inifilenameW, s_quickconnect);
                *FindData = {};
                return BuildActiveSessionsListing(FindData);
            }
        }

        // [Imports] magic folder — umbrella at Path == "\[Imports]" lists
        // every registered adapter; a deeper path routes to the per-source
        // listing (source root, cache subfolder, or [Manage custom locations]).
        // An unrecognised source segment is treated as path-not-found rather
        // than falling through to the normal session/folder resolver.
        {
            std::string sourceId, subPath;
            const ImportsPathKind kind = ClassifyImportsPath(Path,
                &sourceId, &subPath);
            switch (kind) {
                case ImportsPathKind::NotImports:
                    break;
                case ImportsPathKind::Umbrella:
                    *FindData = {};
                    return BuildImportsUmbrellaListing(FindData);
                case ImportsPathKind::SourceRoot:
                case ImportsPathKind::SourceSubPath:
                    *FindData = {};
                    return BuildImportsSourceListing(sourceId, subPath, FindData);
                case ImportsPathKind::UnknownSource:
                    SetLastError(ERROR_NO_MORE_FILES);
                    return INVALID_HANDLE_VALUE;
            }
        }

        // Plugin-side folder navigation: the path is not a real session but a
        // grouping prefix that contains at least one saved session. Resolver
        // classifies this as PathKind::Folder with a non-empty displayName.
        // Refresh the in-memory session list first so the resolver, and the
        // connect below (a session saved since, or a URL), see any sessions
        // saved since the last enumeration.
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

        // Disable reading only within an active server context.
        if (disablereading && IsMainThread()) {
            SetLastError(ERROR_NO_MORE_FILES);
            return INVALID_HANDLE_VALUE;
        }
        wilcopy(pathA.data(), Path, pathA.size() - 1);
        GetDisplayNameFromPath(pathA.data(), displayName.data(), displayName.size() - 1);
        serverid = static_cast<pConnectSettings>(GetServerIdFromName(displayName.data(), GetCurrentThreadId()));
        bool wasconnected = serverid != nullptr;

        // Stale-session detection: the cached serverid is only trustworthy
        // if the underlying TCP connection is still live. Server reboot,
        // firewall reset, or a half-closed FIN leaves g_servers holding a
        // valid-looking pointer with a dead socket beneath — reusing it
        // sends libssh2 into an EAGAIN retry loop that TC surfaces as
        // "nothing happens on Enter". A cheap select+MSG_PEEK on the raw
        // socket catches that state; on failure this thread's registry
        // entry is dropped so the block below re-runs the implicit connect
        // from scratch. Other threads' connections are not touched.
        if (wasconnected && !IsSessionAlive(serverid)) {
            // A listing still open on this connection (an outer directory
            // of a recursive search or copy) holds pointers into it: this
            // nested listing fails instead, and the drop happens once
            // that listing is closed.
            if (serverid->openFindHandles > 0) {
                SFTP_LOG("FIND", "Stale session for '%s' with %d listing(s) open — not dropped yet",
                         displayName.data(), serverid->openFindHandles);
                SetLastError(ERROR_PATH_NOT_FOUND);
                return INVALID_HANDLE_VALUE;
            }
            SFTP_LOG("FIND", "Stale session detected for '%s' — dropping and reconnecting",
                     displayName.data());
            DisconnectServerForThread(displayName.data(), GetCurrentThreadId());
            serverid = nullptr;
            wasconnected = false;
        }

        if (!wasconnected) {
            // Virtual (Imports-cache-backed) session — recognised by the
            // __vimp_<sourceId>_<hash> alias prefix. FsExecuteFileW's
            // virtual-Enter handler pre-registered the alias in
            // VirtualSessionRegistry before returning FS_EXEC_SYMLINK; we
            // do the actual SSH connect here so TC's navigation-flow
            // progress UI applies just like it does for real sessions.
            // An FsFindFirstW(\__vimp_...) invoked without any prior
            // FsExecuteFileW (TC bookmark, hand-typed path) fails cleanly
            // with PATH_NOT_FOUND rather than opening a connect dialog with
            // empty settings.
            if (sftp::IsVirtualSessionAlias(displayName.data())) {
                auto info = sftp::LookupVirtualSession(displayName.data());
                if (!info) {
                    g_lastFailedFindPath = Path;
                    SetLastError(ERROR_PATH_NOT_FOUND);
                    return INVALID_HANDLE_VALUE;
                }
                const std::string& cachePath =
                    sftp::GetImportCache().CacheFilePath();
                if (cachePath.empty() || RefuseIfDependencyBlocks(info->cacheSection)) {
                    g_lastFailedFindPath = Path;
                    SetLastError(ERROR_PATH_NOT_FOUND);
                    return INVALID_HANDLE_VALUE;
                }
                bool stale = false;
                std::string password = LoadImportedPassword(
                    info->sourceId, info->cacheSection, info->displayName, &stale);
                if (stale) {
                    ShowImportStaleRefusal();
                    g_lastFailedFindPath = Path;
                    SetLastError(ERROR_PATH_NOT_FOUND);
                    return INVALID_HANDLE_VALUE;
                }
                new_serverid = SftpConnectToServer(
                    info->cacheSection.c_str(), cachePath.c_str(),
                    password.empty() ? nullptr : password.c_str(), displayName.data());
                SecureZeroMemory(password.data(), password.size());
                if (!new_serverid) {
                    g_lastFailedFindPath = Path;
                    SetLastError(ERROR_PATH_NOT_FOUND);
                    return INVALID_HANDLE_VALUE;
                }
                serverid = new_serverid;
                SetServerIdForName(displayName.data(),
                    static_cast<SERVERID>(serverid));
            }
            else if (g_inMultiOpTransfer) {
                // During a TC multi-step transfer (RENMOV_MULTI), an unresolved
                // path is almost always TC probing a destination as part of its
                // check-then-create flow — NOT a quick-connect URL the user
                // typed. SftpConnectToServer would open the new-session dialog
                // here (empty fields because nothing is in INI), which is the
                // confusing popup the user reported. Short-circuit: remember the
                // path for FsMkDirW to recognise as the immediate next call, and
                // report "path not found" without prompting.
                g_lastFailedFindPath = Path;
                SetLastError(ERROR_PATH_NOT_FOUND);
                return INVALID_HANDLE_VALUE;
            }
            else {
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
#if SFTP_EXTRA
        if (IsLanPairTransport(serverid)) {
            SFTP_LOG("LAN", "FsFindFirstW LAN path='%s'", unicode_util::wstring_to_utf8(Path).c_str());
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
#endif

        // Retrieve the directory
        SFTP_LOG("FIND", "FsFindFirstW: connection ready, calling SftpFindFirstFileW remotedir='%s'", unicode_util::wstring_to_utf8(remotedir.data()).c_str());
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
            return CreateLastFindHandle(ok ? sftpdataptr : nullptr, serverid);
        }
        if (!ok) {
            // newConnGuard destructor fires: SetServerIdForName(name, nullptr) → close + delete
            SetLastError(ERROR_PATH_NOT_FOUND);
            return INVALID_HANDLE_VALUE;
        }

        newConnGuard.commit();  // directory listing succeeded: connection is permanent
        if (SFTP_OK == SftpFindNextFileW(serverid, sftpdataptr, FindData)) {
            return CreateLastFindHandle(sftpdataptr, serverid);
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
        pLastFindStuct lf = (pLastFindStuct)Hdl;
        if (!lf || lf == INVALID_HANDLE_VALUE)
            return false;

        if (lf->isPluginFolder) {
            auto* state = static_cast<PluginFolderFindState*>(lf->sftpdataptr);
            if (!state || state->index >= state->entries.size())
                return false;
            FillFindDataFromPluginEntry(*FindData, state->entries[state->index++]);
            return true;
        }
#if SFTP_EXTRA
        if (lf->isLanPair) {
            auto* state = static_cast<LanPairFindState*>(lf->sftpdataptr);
            if (!state || state->index >= state->entries.size())
                return false;
            LanFillFindData(FindData, state->entries[state->index++]);
            return true;
        }
#endif
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
        WIN32_FIND_DATAW FindDataW{};
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
#if SFTP_EXTRA
        } else if (lf->isLanPair) {
            delete static_cast<LanPairFindState*>(lf->sftpdataptr);
            lf->sftpdataptr = nullptr;
#endif
        } else if (lf->sftpdataptr) {
            SftpFindClose(lf->serverid, lf->sftpdataptr);
            lf->sftpdataptr = nullptr;
        }
        delete lf;
        return 0;
    });
}

BOOL WINAPI FsMkDirW(LPCWSTR Path)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FALSE, [&]() -> BOOL {
        std::wstring aliasPath;
        UseAliasPath(Path, aliasPath);

        const std::wstring_view pathView = Path ? std::wstring_view(Path) : std::wstring_view{};
        if (pathView.size() < 2)
            return false;

        // Block F7 (create folder / new session) anywhere under \[Imports]\.
        // The magic folder mirrors source-program state — the plugin does not
        // create sessions there; it only surfaces them. Users promote a
        // virtual session into their own INI with F5 (materialise).
        if (IsImportsPath(Path))
            return false;

        // F7 inside [Proxies] creates a record instead of a folder. TC has
        // already asked for a name and it is ignored: a record is identified
        // by its number and described by its own settings, so the editor
        // decides what the row will read. Cancelling the editor leaves
        // nothing behind, which is why the return value follows it.
        {
            std::string proxyEntry;
            if (IsProxiesPath(Path, &proxyEntry))
                return CreateProxyRecordDialog(inifilename) != 0;
        }

        // Folder-aware routing: classify the path via the resolver.
        // SessionWithSubpath → real server-side mkdir on the remote.
        // SessionLeaf / Folder → name collision, refuse.
        // Invalid → treat as "new session under the current namespace position",
        // letting the (possibly slash-separated) DisplayName carry the folder
        // prefix automatically.
        const PathResolution r = ResolvePathKindW(Path);

        if (r.kind == PathKind::SessionWithSubpath) {
            std::wstring remotedir(wdirtypemax, L'\0');
            pConnectSettings serverid = GetServerIdAndRelativePathFromPathW(Path, remotedir.data(), remotedir.size() - 1);
            remotedir.resize(wcslen(remotedir.data()));
            if (!serverid)
                return false;
            SessionContextGuard _sessionGuard(serverid);
#if SFTP_EXTRA
            if (IsLanPairTransport(serverid)) {
                if (!serverid->lanSession || !serverid->lanSession->isConnected()) return false;
                return serverid->lanSession->mkdir(LanRemotePathToUtf8(remotedir.data()));
            }
#endif
            // PHP Agent in TAR mode creates the folder right away too: F7 has no
            // archive to carry it, and a TAR batch holds files only, so an empty
            // folder of a copied tree would otherwise never appear. Unpacking
            // into a folder that already exists is harmless.
            int rc = SftpCreateDirectoryW(serverid, remotedir.data());
            if (rc == SFTP_OK)
                return true;
            // TC says nothing when F7 fails, so the plugin does — only for
            // F7 itself: while a copied tree is created, a folder that is
            // already there is no news. The server's "failure" does not say
            // why, so an existing name is asked for separately; only a clear
            // "it is there" says so, anything else reads as a refusal.
            if (MkDirAskedByUser() && rc != SFTP_ABORT) {
                std::wstring shown = remotedir;
                std::replace(shown.begin(), shown.end(), L'\\', L'/');
                if (QueryRemotePath(serverid, remotedir.c_str()) == RemotePathState::Present)
                    ShowPluginMessageWith(IDS_ERR_DIR_EXISTS, "This folder already exists:\n%s",
                                          shown.c_str(), IDS_TITLE_SFTP, "SFTP");
                else
                    ShowPluginMessageWith(IDS_ERR_DIR_NOT_CREATED,
                                          "The folder could not be created:\n%s\n\n"
                                          "The server refused it; its answer is in the log window.",
                                          shown.c_str(), IDS_TITLE_SFTP, "SFTP");
            }
            return false;
        }

        if (r.kind == PathKind::SessionLeaf || r.kind == PathKind::Folder) {
            // A saved session or a folder grouping already occupies that name.
            // Say so: TC reports nothing of its own when this returns false,
            // and silence reads as the key having been missed.
            ShowPluginMessage(IDS_ERR_SESSION_EXISTS,
                              "Session with this name already exists.\nChoose a different session name.",
                              IDS_TITLE_SFTP, "SFTP");
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
        // A connection made there is kept as the Quick Connection (replacing
        // an earlier one), so the row opens it instead of connecting again.
        if (_stricmp(newDisplay.c_str(), s_quickconnect) == 0 ||
            _stricmp(newDisplay.c_str(), s_f7newconnection) == 0) {
            pConnectSettings quick = SftpConnectToServer(s_quickconnect, inifilename, nullptr);
            LoadServersFromIniW(inifilenameW, s_quickconnect);
            if (quick)
                SetServerIdForName(s_quickconnect, static_cast<SERVERID>(quick));
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
