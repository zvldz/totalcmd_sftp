#pragma once

#include <array>
#include <string>
#include <windows.h>
#include "SftpClient.h"
#include "SftpInternal.h"

// Constants shared across all entry-point TUs.
static constexpr DWORD kHomeSymlinkMode = 0555;
static const HANDLE kFsFindRootSentinel = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(1));

// Globals defined in PluginEntryPoints.cpp, used across all entry-point TUs.
extern char    inifilename[MAX_PATH];
extern wchar_t inifilenameW[MAX_PATH];
extern char    g_wincmdIniPath[MAX_PATH];
extern char    s_f7newconnection[32];
extern std::array<WCHAR, 32> s_f7newconnectionW;
extern std::array<WCHAR, 32> s_quickconnectW;
extern bool    disablereading;
extern bool    freportconnect;
// True while TC is running a multi-step transfer through our plugin
// (RENMOV_MULTI: bulk copy/move). FsMkDir checks this to tell apart
// "user pressed F7 to create a new session" from "TC is auto-creating a
// destination folder mid-transfer" — the latter must not pop the Edit
// Session dialog.
extern bool    g_inMultiOpTransfer;

// Path helpers — defined in PluginEntryPoints.cpp, used across all entry-point TUs.
pConnectSettings GetServerIdAndRelativePathFromPath(LPCSTR Path, LPSTR RelativePath, size_t maxlen);
pConnectSettings GetServerIdAndRelativePathFromPathW(LPCWSTR Path, LPWSTR RelativePath, size_t maxlen);
void  ResetLastPercent(pConnectSettings ConnectSettings);
void  ApplyTcLanguageToPluginResources(const char* tcIniPath) noexcept;

// LAN path conversion — defined in PluginEntryPointsFind.cpp, also used by PluginEntryPointsFile.cpp.
std::string LanRemotePathToUtf8(LPCWSTR remotedir);

// Magic virtual-folder name shown in the plugin root only while at least one
// session is connected. Entering it lists every active session; F8 on a row
// disconnects that session; F8 on `kDisconnectAllEntry` disconnects all.
inline constexpr const char*    kActiveSessionsFolder  = "[Active Sessions]";
inline constexpr const wchar_t* kActiveSessionsFolderW = L"[Active Sessions]";
inline constexpr const char*    kDisconnectAllEntry    = "[Disconnect All]";

// Path classifier for the [Active Sessions] magic folder. Returns true if
// `path` points at the folder itself (e.g. "\\[Active Sessions]") or at any
// entry inside it; on inside-entry matches the leaf name is converted to a
// narrow ANSI string with backslashes normalised to forward slashes (so
// folder-nested DisplayNames like "home/raspi" round-trip cleanly) and
// written into `outEntry`. On folder-itself matches `outEntry` is cleared.
// Implementation in PluginEntryPointsFind.cpp.
bool IsActiveSessionsPath(LPCWSTR path, std::string* outEntry = nullptr);
