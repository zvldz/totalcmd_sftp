#pragma once

#include <string>
#include <string_view>

typedef LPVOID  SERVERID;
typedef LPVOID  SERVERHANDLE;

// Lifecycle
void ShutdownMultiServer() noexcept;   // FreeServerList
void FreeServerList() noexcept;

// Ini access — Unicode (W) variants accept a pre-computed wide path so that
// the ini file may live under a Unicode directory. The ANSI shims convert
// and delegate to the W variants; prefer the W forms in new code.
int  LoadServersFromIniW(LPCWSTR inifilename, LPCSTR quickconnectname) noexcept;
bool DeleteServerFromIniW(LPCSTR servername, LPCWSTR inifilename) noexcept;
int  CopyMoveServerInIniW(LPCSTR oldservername, LPCSTR newservername, bool Move, bool OverWrite, LPCWSTR inifilename) noexcept;

int  LoadServersFromIni(LPCSTR inifilename, LPCSTR quickconnectname) noexcept;
int  CopyMoveServerInIni(LPCSTR oldservername, LPCSTR newservername, bool Move, bool OverWrite, LPCSTR inifilename) noexcept;

// Server id lookup / registration
SERVERID GetServerIdFromName(LPCSTR servername, DWORD threadid) noexcept;
bool SetServerIdForName(LPCSTR displayname, SERVERID newid) noexcept;

// Closes the panel's (main-thread) connection to session `name` and drops
// its row, whichever thread calls it — TC can call FsDisconnect from a
// background thread. Connections of running background transfers are left
// alone; each is closed by DisconnectServerForThread when its transfer
// ends. Returns the number of rows removed.
size_t DisconnectServerByName(LPCSTR name) noexcept;

// Closes the connection thread `threadId` holds for session `name` (the
// main thread's or one background thread's) and drops its row.
size_t DisconnectServerForThread(LPCSTR name, DWORD threadId) noexcept;

// Closes every connection a non-main thread `threadId` holds, whatever the
// session. Double Commander copies inside the plugin (FsRenMovFile) in a new
// thread each time, with no background-transfer status around it, so nothing
// else would close the connections it opened. Total Commander uses other
// threads only for background transfers, which close theirs themselves.
size_t DisconnectAllForThread(DWORD threadId) noexcept;

// Copies the secrets the main-thread connection to `name` already holds,
// for a background transfer opening its own connection. False when that
// session is not connected. `phpTar` (optional) receives whether it is a
// PHP Agent session with TAR batches.
struct RuntimeSecrets;
bool CopyMainThreadSecrets(LPCSTR name, RuntimeSecrets& out, bool* phpTar = nullptr) noexcept;

// Copies what the main-thread connection to `name` last listed for
// `relPath` (relative to the session). For custom-column reads from a thread
// that has no connection of its own: Double Commander makes them from a
// thread of its own, Total Commander from the main thread, which finds its
// connection directly. False when the session is not connected or the path
// was not listed.
struct ListingExtra;
bool CopyMainThreadListingExtra(LPCSTR name, std::wstring_view relPath, ListingExtra& out) noexcept;

// Path helpers
void GetDisplayNameFromPath(LPCSTR Path, LPSTR DisplayName, size_t maxlen) noexcept;

// Folder-aware path resolution. Consults the loaded session registry
// (g_servers) and decides what a TC-style path refers to. Used by every
// entry point that must distinguish "session vs folder vs remote sub-path".
//
// Algorithm: normalise leading slashes off and convert '\' to '/', then
// longest-prefix-match against saved session names. If a prefix is a real
// session and equals the full path → SessionLeaf. If a prefix is a real
// session and the path has more segments after it → SessionWithSubpath
// (those segments become `relative`, restored to backslash form). If no
// prefix matches but at least one session starts with `path/` → Folder.
// Otherwise → Invalid.
enum class PathKind {
    SessionLeaf,         // path resolves to a saved session; nothing after
    SessionWithSubpath,  // path enters a saved session and has remote sub-path
    Folder,              // path is a folder prefix containing at least one session
    Invalid,             // path matches nothing in the registry
};

struct PathResolution {
    PathKind    kind = PathKind::Invalid;
    std::string displayName;  // session name (Session*) or folder prefix (Folder); empty for Invalid / root
    std::string relative;     // server sub-path after the session prefix, '\\'-separated; empty unless SessionWithSubpath
};

PathResolution ResolvePathKind(LPCSTR path) noexcept;
PathResolution ResolvePathKindW(LPCWSTR path) noexcept;

// Convert a TC-style path to a canonical session DisplayName form:
// strips leading slashes and converts '\\' separators to '/'. Used when
// constructing the *target* name for create/rename operations where the
// resolver can't yet find the session in the registry (because it doesn't
// exist there until after this call commits).
std::string PathToDisplayNameW(LPCWSTR path) noexcept;

// Whether `name` (an internal string, folders joined by '/') can be given to a
// new or renamed session: a section of sftpplug.ini that reads back as that
// same session and is nothing else. Refused are control characters, '\',
// "$$" (the password manager's separator), spaces at either end (the INI
// trims them), empty or dot folder names, a leading '[' (the plugin's own
// folders) or "__vimp_" (an [Imports] alias), the plugin's own sections
// (Configuration, Imports, proxy, proxyN), and a name inside an existing
// session ("srv/home/x" where "srv" is a session), which no path could reach.
bool IsUsableSessionName(const std::string& name) noexcept;

SERVERHANDLE FindFirstServer(LPSTR displayname, size_t maxlen) noexcept;
SERVERHANDLE FindNextServer(SERVERHANDLE searchhandle, LPSTR displayname, size_t maxlen) noexcept;
void FindCloseServer(SERVERHANDLE searchhandle) noexcept;
