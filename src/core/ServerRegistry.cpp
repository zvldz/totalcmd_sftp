#include "global.h"
#include <windows.h>
#include <stdio.h>
#include <vector>
#include "ServerRegistry.h"
#include "CoreUtils.h"
#include "SftpInternal.h"
#include "PluginEntryPoints.h"
#include "SftpClient.h"
#include "IniFile.h"
#include "UnicodeHelpers.h"
#include <algorithm>
#include <string>
#include <vector>
#include <mutex>
#include <memory>
#include <algorithm>

struct SERVERENTRY {
    std::string name;
    SERVERID serverid = nullptr;
    DWORD threadid = 0;
    bool is_background = false;
};

static std::mutex g_registryMutex;
static std::vector<std::unique_ptr<SERVERENTRY>> g_servers;
// The panel's connections another thread took out of the registry. Only the
// main thread uses them, so only it closes them — between its own calls,
// once no listing it has open still points at one.
static std::vector<pConnectSettings> g_pendingClose;
extern DWORD mainthreadid;

void ShutdownMultiServer() noexcept
{
    FreeServerList();
}

static SERVERENTRY* FindEntry(DWORD tid, LPCSTR name, bool is_bg)
{
    for (const auto& srv : g_servers) {
        if (srv->is_background == is_bg && _stricmp(srv->name.c_str(), name) == 0) {
            if (!is_bg || srv->threadid == tid)
                return srv.get();
        }
    }
    return nullptr;
}

// Closes the pending connections that no open listing holds. Main thread
// only: it runs between that thread's own calls, so nothing else of it is
// using them.
static void ClosePendingOnMainThread() noexcept
{
    if (GetCurrentThreadId() != mainthreadid)
        return;
    std::vector<pConnectSettings> ready;
    {
        std::lock_guard<std::mutex> lock(g_registryMutex);
        for (auto it = g_pendingClose.begin(); it != g_pendingClose.end(); ) {
            if ((*it)->openFindHandles <= 0) {
                ready.push_back(*it);
                it = g_pendingClose.erase(it);
            } else {
                ++it;
            }
        }
    }
    for (auto cs : ready) {
        SftpCloseConnection(cs);
        delete cs;
    }
}

SERVERID GetServerIdFromName(LPCSTR name, DWORD threadId) noexcept
{
    if (!name || !name[0])
        return nullptr;
    ClosePendingOnMainThread();

    std::lock_guard<std::mutex> lock(g_registryMutex);
    
    bool is_bg = (threadId != mainthreadid && threadId != 0);
    SERVERENTRY* entry = FindEntry(threadId, name, is_bg);
    return entry ? entry->serverid : nullptr;
}

// Drops the registry rows `match` selects and closes each distinct
// connection among them once. Every thread owns its own connection object
// (background transfers open their own), so the rows are not assumed to
// share one. Closing happens outside the registry lock: libssh2 shutdown
// can block on sending SSH_MSG_DISCONNECT, and holding the lock through it
// would stall every other session.
template <class Match>
static size_t RemoveAndClose(Match match) noexcept
{
    std::vector<pConnectSettings> toClose;
    size_t removed = 0;
    const bool onMainThread = GetCurrentThreadId() == mainthreadid;
    {
        std::lock_guard<std::mutex> lock(g_registryMutex);
        for (const auto& srv : g_servers) {
            if (!match(*srv) || !srv->serverid)
                continue;
            auto cs = static_cast<pConnectSettings>(srv->serverid);
            // The panel's connection, dropped from another thread: the main
            // thread may be using it this very moment, and its open listings
            // point at it. It closes it itself (ClosePendingOnMainThread).
            if (!srv->is_background && !onMainThread) {
                if (std::find(g_pendingClose.begin(), g_pendingClose.end(), cs) == g_pendingClose.end())
                    g_pendingClose.push_back(cs);
            } else if (std::find(toClose.begin(), toClose.end(), cs) == toClose.end()) {
                toClose.push_back(cs);
            }
            srv->serverid = nullptr;
        }
        const size_t before = g_servers.size();
        g_servers.erase(
            std::remove_if(g_servers.begin(), g_servers.end(),
                [&](const std::unique_ptr<SERVERENTRY>& e) { return match(*e); }),
            g_servers.end());
        removed = before - g_servers.size();
    }
    for (auto cs : toClose) {
        SftpCloseConnection(cs);
        delete cs;
    }
    return removed;
}

size_t DisconnectServerByName(LPCSTR name) noexcept
{
    if (!name || !name[0]) return 0;
    // The panel's connection. Background transfers keep theirs: each closes
    // its own when it ends, and closing it here would pull the connection
    // out from under a running copy.
    return RemoveAndClose([&](const SERVERENTRY& e) {
        return !e.is_background && _stricmp(e.name.c_str(), name) == 0;
    });
}

size_t DisconnectServerForThread(LPCSTR name, DWORD threadId) noexcept
{
    if (!name || !name[0]) return 0;
    const bool is_bg = (threadId != mainthreadid && threadId != 0);
    return RemoveAndClose([&](const SERVERENTRY& e) {
        return e.is_background == is_bg && (!is_bg || e.threadid == threadId) &&
               _stricmp(e.name.c_str(), name) == 0;
    });
}

bool CopyMainThreadSecrets(LPCSTR name, RuntimeSecrets& out, bool* phpTar) noexcept
{
    if (phpTar)
        *phpTar = false;
    if (!name || !name[0])
        return false;
    // Read under the registry lock: a connection is removed from the
    // registry under this lock before it is deleted, so it cannot be freed
    // while being copied here.
    std::lock_guard<std::mutex> lock(g_registryMutex);
    const SERVERENTRY* entry = FindEntry(mainthreadid, name, false);
    if (!entry || !entry->serverid)
        return false;
    const auto cs = static_cast<pConnectSettings>(entry->serverid);
    out.password          = cs->password;
    out.accountPassword   = cs->account_password;
    out.keyPassphrase     = cs->key_passphrase;
    out.jumpKeyPassphrase = cs->jump_key_passphrase;
    out.jumpPassword      = cs->jump_entered_password;
    out.proxyPassword     = cs->proxypassword;
    if (phpTar)
        *phpTar = IsPhpAgentTransport(cs) && cs->php_tar;
    return true;
}

bool SetServerIdForName(LPCSTR name, SERVERID id) noexcept
{
    if (!name || !name[0])
        return false;
        
    pConnectSettings old_cs = nullptr;
    bool success = false;
    {
        std::lock_guard<std::mutex> lock(g_registryMutex);
        DWORD tid = GetCurrentThreadId();
        bool is_bg = (tid != mainthreadid);
        
        SERVERENTRY* entry = FindEntry(tid, name, is_bg);
        
        if (entry) {
            if (entry->serverid != id) {
                old_cs = static_cast<pConnectSettings>(entry->serverid);
            }
            if (id) {
                entry->serverid = id;
            } else {
                entry->serverid = nullptr;
                auto it = std::remove_if(g_servers.begin(), g_servers.end(), [&](const std::unique_ptr<SERVERENTRY>& e) {
                    return e.get() == entry;
                });
                g_servers.erase(it, g_servers.end());
            }
            success = true;
        } else if (id) {
            auto new_entry = std::make_unique<SERVERENTRY>();
            new_entry->name = name;
            new_entry->serverid = id;
            new_entry->threadid = tid;
            new_entry->is_background = is_bg;
            
            if (is_bg) {
                g_servers.insert(g_servers.begin(), std::move(new_entry));
            } else {
                g_servers.push_back(std::move(new_entry));
                auto it_start = std::stable_partition(g_servers.begin(), g_servers.end(), [](const std::unique_ptr<SERVERENTRY>& e) {
                    return e->is_background;
                });
                std::sort(it_start, g_servers.end(), [](const std::unique_ptr<SERVERENTRY>& a, const std::unique_ptr<SERVERENTRY>& b) {
                    return _stricmp(a->name.c_str(), b->name.c_str()) < 0;
                });
            }
            success = true;
        }
    }
    
    if (old_cs) {
        SftpCloseConnection(old_cs);
        delete old_cs;
    }
    
    return success;
}

// INI file paths: a file system path from TC, CP_ACP, not an internal string.
static void AnsiToWide(LPCSTR ansi, wchar_t* wide, int maxlen) noexcept
{
    if (!wide || maxlen <= 0)
        return;
    MultiByteToWideChar(CP_ACP, 0, ansi ? ansi : "", -1, wide, maxlen);
}

int LoadServersFromIniW(LPCWSTR inifilename, LPCSTR quickconnectname) noexcept
{
    std::lock_guard<std::mutex> lock(g_registryMutex);
    
    int servercount = 0;
    std::vector<std::string> ini_servers;
    if (quickconnectname)
        ini_servers.push_back(quickconnectname);

    for (const std::string& section : IniSectionNameList(inifilename)) {
        const std::wstring wp = unicode_util::internal_to_wide(section);
        std::array<wchar_t, 512> serverval{};
        IniGetString(wp.c_str(), L"server", L"", serverval.data(), static_cast<DWORD>(serverval.size()), inifilename);
        const int transferMode = IniGetInt(wp.c_str(), L"transfermode", 0, inifilename);

        if (serverval[0] || transferMode == 3) {
            ini_servers.push_back(section);
        }
    }
    
    auto it = std::remove_if(g_servers.begin(), g_servers.end(), [&](const std::unique_ptr<SERVERENTRY>& e) {
        if (e->is_background || e->serverid != nullptr) return false;
        return std::find_if(ini_servers.begin(), ini_servers.end(), [&](const std::string& name) {
            return _stricmp(name.c_str(), e->name.c_str()) == 0;
        }) == ini_servers.end();
    });
    g_servers.erase(it, g_servers.end());
    
    for (const auto& name : ini_servers) {
        if (!FindEntry(0, name.c_str(), false)) {
            auto new_entry = std::make_unique<SERVERENTRY>();
            new_entry->name = name;
            g_servers.push_back(std::move(new_entry));
            servercount++;
        }
    }
    
    auto it_start = std::stable_partition(g_servers.begin(), g_servers.end(), [](const std::unique_ptr<SERVERENTRY>& e) {
        return e->is_background;
    });
    std::sort(it_start, g_servers.end(), [](const std::unique_ptr<SERVERENTRY>& a, const std::unique_ptr<SERVERENTRY>& b) {
        return _stricmp(a->name.c_str(), b->name.c_str()) < 0;
    });
    
    return servercount;
}

bool DeleteServerFromIniW(LPCSTR servername, LPCWSTR inifilename) noexcept
{
    const std::wstring wsection = unicode_util::internal_to_wide(servername ? servername : "");
    return IniWriteString(wsection.c_str(), nullptr, nullptr, inifilename) != 0;
}

int CopyMoveServerInIniW(LPCSTR oldservername, LPCSTR newservername,
                         bool Move, bool OverWrite, LPCWSTR inifilename) noexcept
{
    if (_stricmp(oldservername, newservername) == 0)
        return FS_FILE_OK;

    const std::wstring woldsect = unicode_util::internal_to_wide(oldservername);
    const std::wstring wnewsect = unicode_util::internal_to_wide(newservername);

    // Read whole, however long: a key list or a value cut short would be
    // copied cut, and a move would then delete the full original. The read
    // reports size - 1 (a value) or size - 2 (a list) when it had to cut.
    const auto readWhole = [&](LPCWSTR key) {
        std::vector<wchar_t> buf(4096);
        for (;;) {
            const DWORD got = IniGetString(woldsect.c_str(), key, L"", buf.data(),
                                           static_cast<DWORD>(buf.size()), inifilename);
            if (got + 2 < buf.size() || buf.size() >= 1024 * 1024)
                return buf;
            buf.assign(buf.size() * 2, L'\0');
        }
    };
    std::vector<wchar_t> captlist;
    try {
        captlist = readWhole(nullptr);
    } catch (...) {
        return FS_FILE_READERROR;
    }
    if (captlist[0]) {
        if (!OverWrite) {
            std::array<wchar_t, 100> testlist{};
            IniGetString(wnewsect.c_str(), nullptr, L"", testlist.data(), static_cast<DWORD>(testlist.size() - 1), inifilename);
            if (testlist[0])
                return FS_FILE_EXISTS;
        }

        DeleteServerFromIniW(newservername, inifilename);

        // The source goes only once every key of the copy is written: on a
        // file that cannot be written the move stops with the session where
        // it was, not with neither.
        bool written = true;
        wchar_t* pcapt = captlist.data();
        while (pcapt[0] && written) {
            try {
                const std::vector<wchar_t> valuebuf = readWhole(pcapt);
                written = IniWriteString(wnewsect.c_str(), pcapt, valuebuf.data(), inifilename) != FALSE;
            } catch (...) {
                written = false;
            }
            pcapt += wcslen(pcapt) + 1;
        }
        if (!written) {
            DeleteServerFromIniW(newservername, inifilename);
            return FS_FILE_WRITEERROR;
        }
        if (Move && !DeleteServerFromIniW(oldservername, inifilename))
            return FS_FILE_WRITEERROR;
        return FS_FILE_OK;
    }
    return FS_FILE_NOTFOUND;
}

int LoadServersFromIni(LPCSTR inifilename, LPCSTR quickconnectname) noexcept
{
    if (!inifilename || !inifilename[0])
        return 0;
    std::array<wchar_t, MAX_PATH> wpath{};
    AnsiToWide(inifilename, wpath.data(), static_cast<int>(wpath.size()));
    return LoadServersFromIniW(wpath.data(), quickconnectname);
}

int CopyMoveServerInIni(LPCSTR oldservername, LPCSTR newservername,
                        bool Move, bool OverWrite, LPCSTR inifilename) noexcept
{
    if (!oldservername || !oldservername[0] || !newservername || !newservername[0] ||
        !inifilename || !inifilename[0]) {
        return FS_FILE_NOTFOUND;
    }
    std::array<wchar_t, MAX_PATH> wpath{};
    AnsiToWide(inifilename, wpath.data(), static_cast<int>(wpath.size()));
    return CopyMoveServerInIniW(oldservername, newservername, Move, OverWrite, wpath.data());
}

void FreeServerList() noexcept
{
    std::vector<pConnectSettings> to_close;
    {
        std::lock_guard<std::mutex> lock(g_registryMutex);
        to_close.swap(g_pendingClose);
        for (auto& entry : g_servers) {
            if (entry->serverid) {
                to_close.push_back(static_cast<pConnectSettings>(entry->serverid));
                entry->serverid = nullptr;
            }
        }
        g_servers.clear();
    }
    for (auto cs : to_close) {
        SftpCloseConnection(cs);
        delete cs;
    }
}

void GetDisplayNameFromPath(LPCSTR Path, LPSTR DisplayName, size_t maxlen) noexcept
{
    if (!DisplayName || maxlen == 0) {
        return;
    }
    if (!Path || !Path[0]) {
        DisplayName[0] = '\0';
        return;
    }
    // Folder-aware: ask the resolver for the longest matching session prefix.
    // For flat (slash-free) session names this is the first path segment.
    const PathResolution r = ResolvePathKind(Path);
    if (!r.displayName.empty()) {
        strlcpy(DisplayName, r.displayName.c_str(), maxlen);
        return;
    }
    // Fallback: path doesn't match any known session or folder yet (e.g. a
    // brand-new quick-connect name about to be saved). Use the first path
    // segment so downstream code gets a usable name.
    LPCSTR p = Path;
    while (*p == '\\' || *p == '/')
        p++;
    strlcpy(DisplayName, p, maxlen);
    LPSTR out = DisplayName;
    while (*out && *out != '\\' && *out != '/')
        out++;
    *out = 0;
}

namespace {

std::string NormaliseTcPath(std::string_view path) noexcept
{
    while (!path.empty() && (path.front() == '\\' || path.front() == '/'))
        path.remove_prefix(1);
    std::string out(path);
    std::replace(out.begin(), out.end(), '\\', '/');
    return out;
}

// Rows a path lookup sees: the panel's, and the calling thread's own
// background rows, so a background transfer still finds its session after
// the panel disconnected it and its row went away.
bool VisibleToCaller(const SERVERENTRY& e) noexcept
{
    return !e.is_background || e.threadid == GetCurrentThreadId();
}

// Returns the canonical (case-preserving) session name if a session exists
// with a case-insensitive match for `name`; empty string otherwise.
// Caller must hold g_registryMutex.
std::string RegistryFindSession(const std::string& name) noexcept
{
    for (const auto& e : g_servers) {
        if (VisibleToCaller(*e) && _stricmp(e->name.c_str(), name.c_str()) == 0)
            return e->name;
    }
    return {};
}

// True if at least one session in the registry has a name starting with
// prefix + "/" (i.e. lives strictly under that folder prefix).
// Caller must hold g_registryMutex.
bool RegistryHasAnyUnderFolder(const std::string& prefix) noexcept
{
    const std::string needle = prefix + "/";
    for (const auto& e : g_servers) {
        if (VisibleToCaller(*e) &&
            e->name.size() > needle.size() &&
            _strnicmp(e->name.c_str(), needle.c_str(), needle.size()) == 0)
            return true;
    }
    return false;
}

}  // anonymous namespace

PathResolution ResolvePathKind(LPCSTR path) noexcept
{
    PathResolution out;
    if (!path)
        return out;
    const std::string norm = NormaliseTcPath(path);

    std::lock_guard<std::mutex> lock(g_registryMutex);

    // Root ("\\" or "/" or empty) → folder, no display name.
    if (norm.empty()) {
        out.kind = PathKind::Folder;
        return out;
    }

    // Longest-prefix-match: full path first, then drop trailing segments.
    std::string candidate = norm;
    while (!candidate.empty()) {
        std::string canonical = RegistryFindSession(candidate);
        if (!canonical.empty()) {
            out.displayName = std::move(canonical);
            if (candidate.size() == norm.size()) {
                out.kind = PathKind::SessionLeaf;
            } else {
                out.kind = PathKind::SessionWithSubpath;
                // After candidate length the next char is '/'; restore to '\'.
                std::string rel = norm.substr(candidate.size());
                std::replace(rel.begin(), rel.end(), '/', '\\');
                out.relative = std::move(rel);
            }
            return out;
        }
        const size_t lastSlash = candidate.find_last_of('/');
        if (lastSlash == std::string::npos)
            break;
        candidate.resize(lastSlash);
    }

    // No session matches; folder iff at least one session lives under it.
    // TC names a folder with a trailing separator too ("\ha\" before a copy
    // into it).
    std::string folder = norm;
    while (!folder.empty() && folder.back() == '/')
        folder.pop_back();
    if (folder.empty()) {
        out.kind = PathKind::Folder;
        return out;
    }
    if (RegistryHasAnyUnderFolder(folder)) {
        out.kind = PathKind::Folder;
        out.displayName = std::move(folder);
    }
    return out;
}

bool IsUsableSessionName(const std::string& name) noexcept
{
    try {
        if (name.empty() || name.front() == ' ' || name.back() == ' ' || name.front() == '[' ||
            name.rfind("__vimp_", 0) == 0 || name.find("$$") != std::string::npos)
            return false;
        for (const char ch : name) {
            const unsigned char c = static_cast<unsigned char>(ch);
            if (c < 0x20 || c == 0x7F || c == '\\')
                return false;
        }
        const auto reserved = [](const std::string& s) {
            if (_stricmp(s.c_str(), "Configuration") == 0 || _stricmp(s.c_str(), "Imports") == 0)
                return true;
            if (_strnicmp(s.c_str(), "proxy", 5) != 0)
                return false;
            return s.find_first_not_of("0123456789", 5) == std::string::npos;
        };
        if (reserved(name))
            return false;
        // Folder segments: none empty or a dot name, and none of the folders
        // above the leaf a session already.
        std::lock_guard<std::mutex> lock(g_registryMutex);
        size_t start = 0;
        for (;;) {
            const size_t slash = name.find('/', start);
            const std::string segment = name.substr(start, slash == std::string::npos ? std::string::npos : slash - start);
            if (segment.empty() || segment == "." || segment == "..")
                return false;
            if (slash == std::string::npos)
                break;
            if (!RegistryFindSession(name.substr(0, slash)).empty())
                return false;
            start = slash + 1;
        }
        // Nor the name of a folder that holds sessions: the session would
        // take the folder's place, and the sessions in it out of reach.
        if (RegistryHasAnyUnderFolder(name))
            return false;
        return true;
    } catch (...) {
        return false;
    }
}

PathResolution ResolvePathKindW(LPCWSTR path) noexcept
{
    if (!path)
        return {};
    const std::string narrow = unicode_util::wide_to_internal(path);
    if (narrow.empty())
        return {};
    return ResolvePathKind(narrow.c_str());
}

std::string PathToDisplayNameW(LPCWSTR path) noexcept
{
    if (!path)
        return {};
    const std::string narrow = unicode_util::wide_to_internal(path);
    if (narrow.empty())
        return {};
    return NormaliseTcPath(narrow);
}

// The session names as they were when the enumeration started: background
// rows inserted or rows erased by other threads meanwhile cannot make it
// skip or repeat a session.
struct ServerEnumContext {
    std::vector<std::string> names;
    size_t next = 0;
};

SERVERHANDLE FindFirstServer(LPSTR displayname, size_t maxlen) noexcept
{
    if (!displayname || maxlen == 0)
        return nullptr;

    try {
        auto ctx = std::make_unique<ServerEnumContext>();
        {
            std::lock_guard<std::mutex> lock(g_registryMutex);
            for (const auto& srv : g_servers)
                if (!srv->is_background)
                    ctx->names.push_back(srv->name);
        }
        if (ctx->names.empty())
            return nullptr;
        strlcpy(displayname, ctx->names[0].c_str(), maxlen);
        ctx->next = 1;
        return static_cast<SERVERHANDLE>(ctx.release());
    } catch (...) {
        return nullptr;
    }
}

SERVERHANDLE FindNextServer(SERVERHANDLE searchhandle, LPSTR displayname, size_t maxlen) noexcept
{
    if (!searchhandle || !displayname || maxlen == 0) return nullptr;
    auto ctx = static_cast<ServerEnumContext*>(searchhandle);
    if (ctx->next < ctx->names.size()) {
        strlcpy(displayname, ctx->names[ctx->next++].c_str(), maxlen);
        return searchhandle;
    }
    delete ctx;
    return nullptr;
}

void FindCloseServer(SERVERHANDLE searchhandle) noexcept
{
    if (searchhandle) {
        auto ctx = static_cast<ServerEnumContext*>(searchhandle);
        delete ctx;
    }
}

