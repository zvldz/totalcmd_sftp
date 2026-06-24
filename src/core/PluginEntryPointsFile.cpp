#include <winsock2.h>
#include <windows.h>
#include <stdlib.h>
#include <array>
#include <memory>
#include <string>
#include <string_view>
#include <algorithm>
#include <vector>
#include "fsplugin.h"
#include "CoreUtils.h"
#include "res/resource.h"
#include "SftpClient.h"
#include "SftpInternal.h"
#include "ServerRegistry.h"
#include "UnicodeHelpers.h"
#include "PluginEntryPoints.h"
#include "ProfileSettings.h"
#include "DllExceptionBarrier.h"
#include "LanPairSession.h"
#include "PluginEntryPointsInternal.h"
#include "PhpAgentClient.h"

// Length (in wide chars) of the session's displayName once embedded in a
// TC-style path — i.e. the number of wchars between the leading '\\' and the
// '\\' that starts the server-side sub-path. Used to truncate RemoteName at
// the session boundary instead of at the first internal slash (which would
// be wrong for folder-nested sessions like "\\folder\\session\\subpath").
static size_t SessionPrefixWideLen(const std::string& displayName) noexcept
{
    if (displayName.empty()) return 0;
    const int wlen = MultiByteToWideChar(CP_ACP, 0, displayName.c_str(), -1,
                                          nullptr, 0);
    return wlen > 1 ? static_cast<size_t>(wlen - 1) : 0;
}

int WINAPI FsExecuteFileW(HWND MainWin, LPWSTR RemoteName, LPCWSTR Verb)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FS_EXEC_ERROR, [&]() -> int {
        std::array<char, wdirtypemax> remoteserver{};
        std::array<WCHAR, wdirtypemax> remotedir{};
        if (_wcsicmp(Verb, L"open") == 0) {   // follow symlink
            // Pseudo helper entry "[F7 = new connection]" opens the
            // new-connection dialog directly, no resolver involvement.
            if (RemoteName[0] && RemoteName[1] &&
                _wcsicmp(RemoteName + 1, s_f7newconnectionW.data()) == 0) {
                pConnectSettings serveridQuick = SftpConnectToServer(s_quickconnect, inifilename, nullptr);
                LoadServersFromIniW(inifilenameW, s_quickconnect);
                return serveridQuick ? FS_EXEC_OK : FS_EXEC_YOURSELF;
            }

            const PathResolution r = ResolvePathKindW(RemoteName);

            // Path enters a session and continues with a server-side sub-path
            // → resolve symlink on the remote.
            if (r.kind == PathKind::SessionWithSubpath) {
                pConnectSettings serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir.data(), remotedir.size() - 1);
                if (!serverid)
                    return FS_EXEC_YOURSELF;

                if (!SftpLinkFolderTargetW(serverid, remotedir.data(), wdirtypemax - 1)) {
                    // Tilde home shortcut — never let TC download it.
                    std::wstring_view rv(remotedir.data());
                    while (!rv.empty() && (rv.front() == L'\\' || rv.front() == L'/'))
                        rv.remove_prefix(1);
                    if (rv == L"~") {
                        // Shell was stale (e.g. after PHP→SCP session switch). Reconnect once and retry.
                        SftpCloseConnection(serverid);
                        Sleep(500);
                        if (SftpConnect(serverid) == SFTP_OK &&
                            SftpLinkFolderTargetW(serverid, remotedir.data(), wdirtypemax - 1)) {
                            // fall through to success path below
                        } else {
                            return FS_EXEC_ERROR;  // fail hard — never download "~" as a file
                        }
                    } else {
                        return FS_EXEC_YOURSELF;
                    }
                }

                // Build the target: session prefix + resolved remote path.
                // Truncate at the session boundary (which can span multiple
                // path segments when the session is in a folder), then append
                // the symlink target the server gave us.
                const size_t prefixLen = SessionPrefixWideLen(r.displayName);
                if (prefixLen == 0 || prefixLen + 1 > wcslen(RemoteName))
                    return FS_EXEC_ERROR;
                RemoteName[1 + prefixLen] = 0;
                wcslcat(RemoteName, remotedir.data(), wdirtypemax-1);
                ReplaceSlashByBackslashW(RemoteName);
                return FS_EXEC_SYMLINK;
            }

            // Path is a leaf session (root-level OR nested in a folder).
            // Lazy-connect (or pick up an existing connection) and expand the
            // path to include the session's last-active / base directory so
            // TC navigates inside the remote filesystem on Enter.
            if (r.kind == PathKind::SessionLeaf) {
                strlcpy(remoteserver.data(), r.displayName.c_str(), remoteserver.size() - 1);
                LPWSTR p = RemoteName + wcslen(RemoteName);
                int pmaxlen = wdirtypemax - static_cast<int>(p - RemoteName) - 1;

                pConnectSettings serverid = static_cast<pConnectSettings>(
                    GetServerIdFromName(remoteserver.data(), GetCurrentThreadId()));
                if (serverid) {
                    SftpGetLastActivePathW(serverid, p, pmaxlen);
                } else if (_stricmp(remoteserver.data(), s_quickconnect) == 0) {
                    // Quick connect: connect here, otherwise the selected sub-path can't be applied.
                    serverid = SftpConnectToServer(remoteserver.data(), inifilename, nullptr);
                    if (!serverid)
                        return FS_EXEC_OK; // cancelled or save-only from quick dialog
                    SetServerIdForName(remoteserver.data(), static_cast<SERVERID>(serverid));
                    SftpGetLastActivePathW(serverid, p, pmaxlen);
                } else {
                    // Convert the (potentially slash-separated) DisplayName to wide
                    // and read the session's base path from INI without connecting.
                    std::array<wchar_t, wdirtypemax> displayNameW{};
                    MultiByteToWideChar(CP_ACP, 0, r.displayName.c_str(), -1,
                                        displayNameW.data(), static_cast<int>(displayNameW.size()));
                    SftpGetServerBasePathW(displayNameW.data(), p, pmaxlen, inifilename);
                }
                if (p[0] == 0)
                    wcslcat(RemoteName, L"/", wdirtypemax-1);
                ReplaceSlashByBackslashW(RemoteName);
                return FS_EXEC_SYMLINK;
            }

            // Folder or Invalid → let TC do whatever it does (folders navigate
            // via FsFindFirstW, not FsExecuteFile, so we usually don't get
            // called for them; invalid paths fall back to TC).
            return FS_EXEC_YOURSELF;
        }
        if (_wcsicmp(Verb, L"properties") == 0) {
            const PathResolution r = ResolvePathKindW(RemoteName);

            // SessionLeaf (root-level OR nested in a folder) → open the Edit
            // Session dialog. Pseudo helper entries are skipped silently.
            if (r.kind == PathKind::SessionLeaf) {
                if (_stricmp(r.displayName.c_str(), s_f7newconnection) != 0 &&
                    _stricmp(r.displayName.c_str(), s_quickconnect)    != 0)
                {
                    if (SftpConfigureServer(r.displayName.c_str(), inifilename)) {
                        LoadServersFromIniW(inifilenameW, s_quickconnect);
                        if (MainWin) PostMessage(MainWin, WM_USER + 51, 540, 0);

                        // Force a disconnect so the next listing rebuilds the
                        // connection with the edited settings (TC by itself
                        // does not drop the active session on Alt+Enter).
                        std::string disconnPath;
                        disconnPath.reserve(r.displayName.size() + 1);
                        disconnPath.append("\\").append(r.displayName);
                        FsDisconnect(disconnPath.c_str());
                    }
                }
                return FS_EXEC_OK;
            }

            // SessionWithSubpath → server-side properties on a real file.
            if (r.kind == PathKind::SessionWithSubpath) {
                std::array<WCHAR, wdirtypemax> remotenameW{};
                pConnectSettings serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotenameW.data(), remotenameW.size() - 1);
                if (serverid)
                    SftpShowPropertiesW(serverid, remotenameW.data());
                else
                    return FS_EXEC_ERROR;
                return FS_EXEC_OK;
            }

            // Folder / Invalid / pseudo entries → nothing useful to show.
            return FS_EXEC_OK;
        }
        if (_wcsnicmp(Verb, L"chmod ", 6) == 0) {
            const PathResolution rc = ResolvePathKindW(RemoteName);
            if (rc.kind == PathKind::SessionWithSubpath) {
                pConnectSettings serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir.data(), remotedir.size() - 1);
                if (serverid && SftpChmodW(serverid, remotedir.data(), Verb+6))
                    return FS_EXEC_OK;
            }
            return FS_EXEC_ERROR;
        }
        if (_wcsnicmp(Verb, L"quote ", 6) == 0) {
            const PathResolution rq = ResolvePathKindW(RemoteName);
            if (wcsncmp(Verb+6, L"cd ", 3) == 0) {
                // first get the start path within the plugin
                pConnectSettings serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir.data(), remotedir.size() - 1);
                if (!serverid)
                    return FS_EXEC_ERROR;
                if (Verb[9] != '\\' && Verb[9] != '/') {     // relative path?
                    wcslcatbackslash(remotedir.data(), remotedir.size() - 1);
                    wcslcat(remotedir.data(), Verb+9, remotedir.size() - 1);
                } else
                    wcslcpy(remotedir.data(), Verb+9, remotedir.size() - 1);
                ReplaceSlashByBackslashW(remotedir.data());

                // Truncate at the session boundary, then append the new dir.
                const size_t prefixLen = SessionPrefixWideLen(rq.displayName);
                if (prefixLen == 0 || prefixLen + 1 > wcslen(RemoteName))
                    return FS_EXEC_ERROR;
                RemoteName[1 + prefixLen] = 0;
                wcslcat(RemoteName, remotedir.data(), wdirtypemax-1);
                ReplaceSlashByBackslashW(RemoteName);
                return FS_EXEC_SYMLINK;
            } else {
                if (rq.kind == PathKind::SessionWithSubpath || rq.kind == PathKind::SessionLeaf) {
                    std::array<WCHAR, wdirtypemax> quoteRemotedir{};
                    pConnectSettings serverid = GetServerIdAndRelativePathFromPathW(RemoteName, quoteRemotedir.data(), quoteRemotedir.size() - 1);
                    if (serverid && SftpQuoteCommand2W(serverid, quoteRemotedir.data(), Verb+6, nullptr, 0) != 0)
                        return FS_EXEC_OK;
                }
            }
            return FS_EXEC_ERROR;
        }
        if (_wcsnicmp(Verb, L"mode ", 5) == 0) {   // Binary/Text/Auto
            SftpSetTransferModeW(Verb+5);
            return FS_EXEC_OK;
        }
        return FS_EXEC_ERROR;
    });
}

int WINAPI FsExecuteFile(HWND MainWin, LPSTR RemoteName, LPCSTR Verb)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FS_EXEC_ERROR, [&]() -> int {
        std::array<WCHAR, wdirtypemax> remoteNameW{};
        std::array<WCHAR, wdirtypemax> verbW{};
        int ret = FsExecuteFileW(MainWin, awlcopy(remoteNameW.data(), RemoteName, remoteNameW.size() - 1), awlcopy(verbW.data(), Verb, verbW.size() - 1));
        if (ret == FS_EXEC_SYMLINK)
            walcopy(RemoteName, remoteNameW.data(), MAX_PATH-1);
        return ret;
    });
}

static bool CopyMoveEncryptedPassword(LPCSTR OldName, LPSTR NewName, bool Move)
{
    if (!CryptProc)
        return false;
    int mode = Move ? FS_CRYPT_MOVE_PASSWORD : FS_CRYPT_COPY_PASSWORD;
    int rc = CryptProc(PluginNumber, CryptoNumber, mode, OldName, NewName, 0);
    return (rc == FS_FILE_OK) ? true : false;
}

int WINAPI FsRenMovFileW(LPCWSTR OldName, LPCWSTR NewName, BOOL Move, BOOL OverWrite, RemoteInfoStruct * ri)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FS_FILE_WRITEERROR, [&]() -> int {
        const PathResolution rOld = ResolvePathKindW(OldName);
        const PathResolution rNew = ResolvePathKindW(NewName);

        // --- 1. Session rename / move ---
        // Covers all of: flat-flat rename, flat→folder move, folder→flat move,
        // and cross-folder move. The new DisplayName comes from the path
        // itself (PathToDisplayName), since the destination session can't
        // exist in the registry yet (otherwise we'd be overwriting).
        if (rOld.kind == PathKind::SessionLeaf) {
            const std::string newDisplay = PathToDisplayNameW(NewName);
            if (newDisplay.empty())
                return FS_FILE_NOTFOUND;
            if (_stricmp(rOld.displayName.c_str(), newDisplay.c_str()) == 0)
                return FS_FILE_OK;
            if (!OverWrite && (rNew.kind == PathKind::SessionLeaf ||
                               rNew.kind == PathKind::Folder))
                return FS_FILE_EXISTS;

            // Disconnect the live connection (if any) before yanking the INI
            // section out from under it — see the original F6 rename note.
            if (Move) {
                std::string disconnPath;
                disconnPath.reserve(rOld.displayName.size() + 1);
                disconnPath.append("\\").append(rOld.displayName);
                FsDisconnect(disconnPath.c_str());
            }
            int rc = CopyMoveServerInIniW(rOld.displayName.c_str(),
                                          newDisplay.c_str(),
                                          !!Move, !!OverWrite, inifilenameW);
            if (rc == FS_FILE_OK) {
                std::string newDisplayMut = newDisplay;
                CopyMoveEncryptedPassword(rOld.displayName.c_str(),
                                          newDisplayMut.data(), !!Move);
                if (Move) {
                    UpdateJumpRefsOnSessionRename(rOld.displayName.c_str(),
                                                  newDisplay.c_str(),
                                                  inifilename);
                }
                LoadServersFromIniW(inifilenameW, s_quickconnect);
                HWND hTcMain = FindWindowA("TTOTAL_CMD", nullptr);
                if (hTcMain) PostMessage(hTcMain, WM_USER + 51, 540, 0);
                return FS_FILE_OK;
            }
            if (rc == FS_FILE_EXISTS)
                return FS_FILE_EXISTS;
            return FS_FILE_NOTFOUND;
        }

        // --- 2. Folder rename / move (bulk) ---
        // Every saved session whose name starts with `oldPrefix + "/"` is
        // renamed to `newPrefix + "/" + leaf`, with jump-host references
        // updated by prefix.
        if (rOld.kind == PathKind::Folder && !rOld.displayName.empty()) {
            const std::string newFolder = PathToDisplayNameW(NewName);
            if (newFolder.empty())
                return FS_FILE_NOTFOUND;
            if (_stricmp(rOld.displayName.c_str(), newFolder.c_str()) == 0)
                return FS_FILE_OK;
            if (!OverWrite && (rNew.kind == PathKind::SessionLeaf ||
                               rNew.kind == PathKind::Folder))
                return FS_FILE_EXISTS;

            // Build the {old, new} rename list up front so we don't mutate
            // INI while enumerating its section list.
            std::vector<std::pair<std::string, std::string>> renames;
            {
                std::array<wchar_t, 65535> serverlist{};
                GetPrivateProfileStringW(nullptr, nullptr, L"", serverlist.data(),
                                          static_cast<DWORD>(serverlist.size()),
                                          inifilenameW);
                const std::string needle = rOld.displayName + "/";
                wchar_t* wp = serverlist.data();
                while (wp[0]) {
                    std::array<char, MAX_PATH> sectionA{};
                    WideCharToMultiByte(CP_ACP, 0, wp, -1, sectionA.data(),
                                         static_cast<int>(sectionA.size()),
                                         nullptr, nullptr);
                    const size_t len = strlen(sectionA.data());
                    if (len > needle.size() &&
                        _strnicmp(sectionA.data(), needle.c_str(), needle.size()) == 0) {
                        std::string oldName(sectionA.data(), len);
                        std::string newName = newFolder + "/" + (sectionA.data() + needle.size());
                        renames.emplace_back(std::move(oldName), std::move(newName));
                    }
                    wp += wcslen(wp) + 1;
                }
            }
            if (renames.empty())
                return FS_FILE_NOTFOUND;

            for (const auto& [oldName, newName] : renames) {
                if (Move) {
                    std::string disconnPath;
                    disconnPath.reserve(oldName.size() + 1);
                    disconnPath.append("\\").append(oldName);
                    FsDisconnect(disconnPath.c_str());
                }
                CopyMoveServerInIniW(oldName.c_str(), newName.c_str(),
                                      !!Move, !!OverWrite, inifilenameW);
                std::string newNameMut = newName;
                CopyMoveEncryptedPassword(oldName.c_str(), newNameMut.data(), !!Move);
            }
            if (Move) {
                UpdateJumpRefsOnFolderRename(rOld.displayName.c_str(),
                                              newFolder.c_str(), inifilename);
            }
            LoadServersFromIniW(inifilenameW, s_quickconnect);
            HWND hTcMain = FindWindowA("TTOTAL_CMD", nullptr);
            if (hTcMain) PostMessage(hTcMain, WM_USER + 51, 540, 0);
            return FS_FILE_OK;
        }

        // --- 3. Server-side rename (file / directory inside a session) ---
        std::wstring olddir(wdirtypemax, L'\0');
        std::wstring newdir(wdirtypemax, L'\0');
        pConnectSettings serverid1 = GetServerIdAndRelativePathFromPathW(OldName, olddir.data(), olddir.size() - 1);
        pConnectSettings serverid2 = GetServerIdAndRelativePathFromPathW(NewName, newdir.data(), newdir.size() - 1);
        olddir.resize(wcslen(olddir.data()));
        newdir.resize(wcslen(newdir.data()));

        // Source and destination must be on the same server.
        if (serverid1 != serverid2 || serverid1 == nullptr)
            return FS_FILE_NOTFOUND;

        ResetLastPercent(serverid1);
        SessionContextGuard _sessionGuard(serverid1);

        bool isdir = (ri->Attr & FILE_ATTRIBUTE_DIRECTORY) ? true : false;

        // LAN Pair rename.
        if (IsLanPairTransport(serverid1)) {
            if (!serverid1->lanSession || !serverid1->lanSession->isConnected()) return FS_FILE_WRITEERROR;
            const std::string oldUtf8 = LanRemotePathToUtf8(olddir.data());
            const std::string newUtf8 = LanRemotePathToUtf8(newdir.data());
            return serverid1->lanSession->rename(oldUtf8, newUtf8) ? FS_FILE_OK : FS_FILE_WRITEERROR;
        }

        int rc = SftpRenameMoveFileW(serverid1, olddir.data(), newdir.data(), !!Move, !!OverWrite, isdir);
        switch (rc) {
        case SFTP_OK:
            return FS_FILE_OK;
        case SFTP_EXISTS:
            return FS_FILE_EXISTS;
        default:
            return FS_FILE_WRITEERROR;
        }
    });
}

int WINAPI FsRenMovFile(LPCSTR OldName, LPCSTR NewName, BOOL Move, BOOL OverWrite, RemoteInfoStruct * ri)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FS_FILE_WRITEERROR, [&]() -> int {
        std::array<WCHAR, wdirtypemax> oldNameW{};
        std::array<WCHAR, wdirtypemax> newNameW{};
        return FsRenMovFileW(awlcopy(oldNameW.data(), OldName, oldNameW.size() - 1), awlcopy(newNameW.data(), NewName, newNameW.size() - 1), Move, OverWrite, ri);
    });
}

static bool FileExistsT(LPCWSTR LocalName)
{
    WIN32_FIND_DATAW s;
    HANDLE findhandle = FindFirstFileT(LocalName, &s);
    if (!findhandle || findhandle == INVALID_HANDLE_VALUE)
        return false;
    FindClose(findhandle);
    return true;
}

static void SanitizeLocalFileNameW(LPWSTR localPath) noexcept
{
    if (!localPath || !localPath[0])
        return;
    const std::wstring_view pathView(localPath);
    const size_t slashPos = pathView.find_last_of(L"\\/");
    if (slashPos == std::wstring_view::npos || slashPos + 1 >= pathView.size())
        return;
    wchar_t* filePart = localPath + slashPos + 1;
    while (*filePart) {
        if (static_cast<unsigned>(*filePart) < 32u) {
            *filePart = L' ';
        } else if (*filePart == L':' || *filePart == L'|' || *filePart == L'*' || *filePart == L'?' ||
                   *filePart == L'\\' || *filePart == L'/' || *filePart == L'"') {
            *filePart = L'_';
        }
        ++filePart;
    }
}

static int CreateHelpFileLocalW(LPCWSTR localName, bool overwrite)
{
    const DWORD disposition = overwrite ? CREATE_ALWAYS : CREATE_NEW;
    handle_util::FileHandle outFile(CreateFileT(
        localName,
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        disposition,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr));

    if (!outFile) {
        const DWORD gle = GetLastError();
        if (gle == ERROR_ALREADY_EXISTS || gle == ERROR_FILE_EXISTS)
            return FS_FILE_EXISTS;
        return FS_FILE_WRITEERROR;
    }

    std::array<char, 256> helpText{};
    LoadString(hinst, IDS_HELPTEXT, helpText.data(), static_cast<int>(helpText.size()));
    DWORD written = 0;
    const BOOL ok = WriteFile(outFile.get(), helpText.data(),
                              static_cast<DWORD>(strlen(helpText.data())), &written, nullptr);
    return ok ? FS_FILE_OK : FS_FILE_WRITEERROR;
}

int WINAPI FsGetFileW(LPCWSTR RemoteName, LPWSTR LocalName, int CopyFlags, RemoteInfoStruct * ri)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FS_FILE_READERROR, [&]() -> int {
        const bool OverWrite = !!(CopyFlags & FS_COPYFLAGS_OVERWRITE);
        bool Resume = !!(CopyFlags & FS_COPYFLAGS_RESUME);
        const bool Move = !!(CopyFlags & FS_COPYFLAGS_MOVE);
        SFTP_LOG("ENTRY", "FsGetFileW start flags=0x%x overwrite=%d resume=%d move=%d shift=%d",
                 CopyFlags, OverWrite ? 1 : 0, Resume ? 1 : 0, Move ? 1 : 0,
                 (GetAsyncKeyState(VK_SHIFT) & 0x8000) ? 1 : 0);

        const std::wstring_view remoteView = RemoteName ? std::wstring_view(RemoteName) : std::wstring_view{};
        if (remoteView.size() < 3 || !LocalName || !ri)
            return FS_FILE_NOTFOUND;

        if (remoteView.substr(1) == std::wstring_view(s_f7newconnectionW.data())) {
            return CreateHelpFileLocalW(LocalName, OverWrite);
        }

        // F3/F4 on a saved-session entry (root-level OR nested in a folder)
        // → open the Edit Session dialog instead of downloading the entry as
        // a file. Same effect as RMB → Properties / Alt+Enter, but reachable
        // from the keyboard.
        //
        // TC's View/Edit always wants a downloaded file: any non-OK return
        // shows "Error downloading file", and FS_FILE_OK makes TC open the
        // viewer/editor on the temp file afterwards (this cannot be
        // suppressed — confirmed against the Registry plugin's behaviour).
        // So after the dialog we write a short stub note into the temp file
        // and return OK: no error, and the trailing viewer/editor shows a
        // self-explanatory message instead of misleading editable settings.
        {
            const PathResolution r = ResolvePathKindW(RemoteName);
            if (r.kind == PathKind::SessionLeaf &&
                _stricmp(r.displayName.c_str(), s_f7newconnection) != 0 &&
                _stricmp(r.displayName.c_str(), s_quickconnect)    != 0)
            {
                if (SftpConfigureServer(r.displayName.c_str(), inifilename)) {
                    LoadServersFromIniW(inifilenameW, s_quickconnect);
                    // Drop any active session so the next listing rebuilds it
                    // with the edited settings (mirrors the properties path).
                    std::string disconnPath;
                    disconnPath.reserve(r.displayName.size() + 1);
                    disconnPath.append("\\").append(r.displayName);
                    FsDisconnect(disconnPath.c_str());
                }
                // Stub note for the viewer/editor TC opens after FS_FILE_OK.
                std::string note = "Session '";
                note.append(r.displayName);
                note.append("' was opened for editing in a dialog.\r\n"
                             "This file is not used \xE2\x80\x94 you can close this window.\r\n");
                HANDLE hStub = CreateFileW(LocalName, GENERIC_WRITE, 0, nullptr,
                                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
                if (hStub != INVALID_HANDLE_VALUE) {
                    DWORD written = 0;
                    WriteFile(hStub, note.data(), static_cast<DWORD>(note.size()), &written, nullptr);
                    CloseHandle(hStub);
                }
                return FS_FILE_OK;
            }
        }

        SanitizeLocalFileNameW(LocalName);

        std::wstring remotedir(wdirtypemax, L'\0');
        pConnectSettings serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir.data(), remotedir.size() - 1);
        if (serverid == nullptr)
            return FS_FILE_READERROR;

        // Prefix all ShowStatus output in this thread with "[<session>] ".
        SessionContextGuard _sessionGuard(serverid);

        int startPct = 0;
        if (Resume && ri && ri->Size64 > 0) {
            HANDLE h = CreateFileW(LocalName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                   nullptr, OPEN_EXISTING, 0, nullptr);
            if (h != INVALID_HANDLE_VALUE) {
                LARGE_INTEGER li{};
                if (GetFileSizeEx(h, &li) && li.QuadPart > 0)
                    startPct = (int)std::clamp((li.QuadPart * 100LL) / ri->Size64, 0LL, 100LL);
                CloseHandle(h);
            }
        }

        serverid->lastpercent = startPct;

        int err = ProgressProcT(PluginNumber, RemoteName, LocalName, startPct);
        if (err)
            return FS_FILE_USERABORT;
        if (!OverWrite && !Resume && FileExistsT(LocalName)) {
            bool TextMode = (serverid->unixlinebreaks == 1) && SftpDetermineTransferModeW(RemoteName);
            if (TextMode)
                return FS_FILE_NOTSUPPORTED;
            return FS_FILE_EXISTSRESUMEALLOWED;
        }
        if (OverWrite) {
            DeleteFileT(LocalName);
        }

        // PHP Agent TAR batch download: queue single file instead of downloading individually.
        if (ri && !(ri->Attr & FILE_ATTRIBUTE_DIRECTORY) &&
            IsPhpAgentTransport(serverid) && serverid->php_tar &&
            TarDownloadSessionIsActive(serverid))
        {
            if (TarDownloadSessionQueue(serverid, LocalName, remotedir.data()))
                return FS_FILE_OK;
        }

        // PHP Agent TAR directory download.
        if (ri && (ri->Attr & FILE_ATTRIBUTE_DIRECTORY) &&
            IsPhpAgentTransport(serverid) && serverid->php_tar)
        {
            CreateDirectoryW(LocalName, nullptr);
            const int rc = PhpAgentDownloadDirAsTar(serverid, remotedir.data(), LocalName, OverWrite);
            if (rc == SFTP_OK)    return FS_FILE_OK;
            if (rc == SFTP_ABORT) return FS_FILE_USERABORT;
            // On any error fall through to TC-managed recursion.
            return FS_FILE_NOTSUPPORTED;
        }

        // LAN Pair download.
        if (IsLanPairTransport(serverid)) {
            if (!serverid->lanSession || !serverid->lanSession->isConnected())
                return FS_FILE_READERROR;
            const std::string remoteUtf8 = LanRemotePathToUtf8(remotedir.data());
            int fsResult = FS_FILE_READERROR;
            serverid->lanSession->getFile(remoteUtf8, LocalName,
                                          ri ? ri->Size64 : 0,
                                          ri ? &ri->LastWriteTime : nullptr,
                                          OverWrite, Resume, &fsResult);
            return fsResult;
        }

        while (true) {  // auto-resume loop
            int rc = SftpDownloadFileW(serverid, remotedir.data(), LocalName, true, ri->Size64, &ri->LastWriteTime, Resume);
            SFTP_LOG("ENTRY", "FsGetFileW SftpDownloadFileW rc=%d", rc);
            switch (rc) {
                case SFTP_OK:          return FS_FILE_OK;
                case SFTP_EXISTS:      return FS_FILE_EXISTS;
                case SFTP_READFAILED:  return FS_FILE_READERROR;
                case SFTP_WRITEFAILED: return FS_FILE_WRITEERROR;
                case SFTP_ABORT:       return FS_FILE_USERABORT;
                case SFTP_PARTIAL:     Resume = true; break;
                default:               return FS_FILE_READERROR;
            }
        }
        return FS_FILE_OK;
    });
}

int WINAPI FsGetFile(LPCSTR RemoteName, LPSTR LocalName, int CopyFlags, RemoteInfoStruct* ri)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FS_FILE_READERROR, [&]() -> int {
        if (!RemoteName || !LocalName || !ri)
            return FS_FILE_NOTFOUND;
        std::array<WCHAR, wdirtypemax> remoteNameW{};
        std::array<WCHAR, wdirtypemax> localNameW{};
        return FsGetFileW(awlcopy(remoteNameW.data(), RemoteName, remoteNameW.size() - 1), awlcopy(localNameW.data(), LocalName, localNameW.size() - 1), CopyFlags, ri);
    });
}

int WINAPI FsPutFileW(LPCWSTR LocalName, LPCWSTR RemoteName, int CopyFlags)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FS_FILE_WRITEERROR, [&]() -> int {
        const bool OverWrite = !!(CopyFlags & FS_COPYFLAGS_OVERWRITE);
        const bool Resume = !!(CopyFlags & FS_COPYFLAGS_RESUME);
        const bool Move = !!(CopyFlags & FS_COPYFLAGS_MOVE);
        SFTP_LOG("ENTRY", "FsPutFileW start flags=0x%x overwrite=%d resume=%d move=%d shift=%d",
                 CopyFlags, OverWrite ? 1 : 0, Resume ? 1 : 0, Move ? 1 : 0,
                 (GetAsyncKeyState(VK_SHIFT) & 0x8000) ? 1 : 0);

        const std::wstring_view localView = LocalName ? std::wstring_view(LocalName) : std::wstring_view{};
        const std::wstring_view remoteView = RemoteName ? std::wstring_view(RemoteName) : std::wstring_view{};

        // Auto-overwrites files -> return error if file exists
        if ((CopyFlags & (FS_COPYFLAGS_EXISTS_SAMECASE | FS_COPYFLAGS_EXISTS_DIFFERENTCASE)) != 0) {
            if (!OverWrite && !Resume) {
                return FS_FILE_EXISTSRESUMEALLOWED;
            }
        }

        if (remoteView.size() < 3 || localView.empty())
            return FS_FILE_WRITEERROR;

        int err = ProgressProcT(PluginNumber, LocalName, RemoteName, 0);
        if (err)
            return FS_FILE_USERABORT;

        std::array<WCHAR, wdirtypemax> remotedir{};
    
        pConnectSettings serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir.data(), remotedir.size() - 1);
        if (serverid == nullptr)
            return FS_FILE_READERROR;
        ResetLastPercent(serverid);

        // Prefix all ShowStatus output in this thread with "[<session>] ".
        SessionContextGuard _sessionGuard(serverid);

        // LAN Pair upload.
        if (IsLanPairTransport(serverid)) {
            if (!serverid->lanSession || !serverid->lanSession->isConnected())
                return FS_FILE_WRITEERROR;
            const std::string remoteUtf8 = LanRemotePathToUtf8(remotedir.data());
            int fsResult = FS_FILE_WRITEERROR;
            serverid->lanSession->putFile(LocalName, remoteUtf8, OverWrite, Resume, &fsResult);
            return fsResult;
        }

        // PHP Agent TAR batch upload: queue file into session, send all as one TAR at FsStatusInfo END.
        if (IsPhpAgentTransport(serverid) && serverid->php_tar && TarUploadSessionIsActive()) {
            // Fill in cs on first file if session was started without one (PUT_MULTI_THREAD).
            if (!TarUploadSessionIsActive(serverid))
                TarUploadSessionBegin(serverid);
            const std::string remoteRelA = unicode_util::wide_to_narrow(remotedir.data());
            SFTP_LOG("TAR", "FsPutFileW queued '%S' -> '%s'", LocalName, remoteRelA.c_str());
            TarUploadSessionQueue(serverid, LocalName, remoteRelA.c_str());
            return FS_FILE_OK;
        }
        SFTP_LOG("TAR", "FsPutFileW TAR skip: isPhpAgent=%d php_tar=%d tarActive=%d",
                 IsPhpAgentTransport(serverid) ? 1 : 0,
                 serverid->php_tar ? 1 : 0,
                 TarUploadSessionIsActive() ? 1 : 0);

        const bool setattr = !!(CopyFlags & FS_COPYFLAGS_EXISTS_SAMECASE);
        int rc = SftpUploadFileW(serverid, LocalName, remotedir.data(), Resume, setattr);
        SFTP_LOG("ENTRY", "FsPutFileW SftpUploadFileW rc=%d", rc);
        switch (rc) {
            case SFTP_OK:          return FS_FILE_OK;
            case SFTP_EXISTS:      return SftpSupportsResume(serverid) ? FS_FILE_EXISTSRESUMEALLOWED : FS_FILE_EXISTS;
            case SFTP_READFAILED:  return FS_FILE_READERROR;
            case SFTP_WRITEFAILED: return FS_FILE_WRITEERROR;
            case SFTP_ABORT:       return FS_FILE_USERABORT;
            default:               return FS_FILE_WRITEERROR;
        }
        return FS_FILE_WRITEERROR;
    });
}

int WINAPI FsPutFile(LPCSTR LocalName, LPCSTR RemoteName, int CopyFlags)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FS_FILE_WRITEERROR, [&]() -> int {
        if (!LocalName || !RemoteName)
            return FS_FILE_WRITEERROR;
        std::array<WCHAR, wdirtypemax> localNameW{};
        std::array<WCHAR, wdirtypemax> remoteNameW{};
        return FsPutFileW(awlcopy(localNameW.data(), LocalName, localNameW.size() - 1), awlcopy(remoteNameW.data(), RemoteName, remoteNameW.size() - 1), CopyFlags);
    });
}

BOOL WINAPI FsDeleteFileW(LPCWSTR RemoteName)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FALSE, [&]() -> BOOL {
        const std::wstring_view remoteView = RemoteName ? std::wstring_view(RemoteName) : std::wstring_view{};
        if (remoteView.size() < 2)
            return false;

        const PathResolution r = ResolvePathKindW(RemoteName);

        // Real file inside a session → server-side delete.
        if (r.kind == PathKind::SessionWithSubpath) {
            std::wstring remotedir(wdirtypemax, L'\0');
            pConnectSettings serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir.data(), remotedir.size() - 1);
            remotedir.resize(wcslen(remotedir.data()));
            if (serverid == nullptr)
                return false;
            ResetLastPercent(serverid);
            SessionContextGuard _sessionGuard(serverid);
            if (IsLanPairTransport(serverid)) {
                if (!serverid->lanSession || !serverid->lanSession->isConnected()) return false;
                return serverid->lanSession->remove(LanRemotePathToUtf8(remotedir.data()));
            }
            int rc = SftpDeleteFileW(serverid, remotedir.data(), false);
            return (rc == SFTP_OK) ? true : false;
        }

        // Saved-session entry (root-level OR nested in a folder) → drop the
        // INI section. Refuse the pseudo helper entries which are not real
        // sessions and don't have an INI section to remove.
        if (r.kind == PathKind::SessionLeaf) {
            if (_stricmp(r.displayName.c_str(), s_f7newconnection) == 0 ||
                _stricmp(r.displayName.c_str(), s_quickconnect) == 0)
                return false;
            // Disconnect any active connection under this name first so the
            // registry doesn't preserve a ghost entry (LoadServersFromIniW
            // keeps entries with a non-null serverid even after the INI
            // section is gone, which would leave the deleted session
            // visible in subsequent listings).
            {
                std::string disconnPath;
                disconnPath.reserve(r.displayName.size() + 1);
                disconnPath.append("\\").append(r.displayName);
                FsDisconnect(disconnPath.c_str());
            }
            if (DeleteServerFromIniW(r.displayName.c_str(), inifilenameW)) {
                if (CryptProc)
                    CryptProc(PluginNumber, CryptoNumber, FS_CRYPT_DELETE_PASSWORD,
                              const_cast<char*>(r.displayName.c_str()), nullptr, 0);
                // Clear any jump-host references that pointed at the deleted
                // session so the by-reference picker doesn't surface them as
                // "[!] (missing)" markers afterwards.
                UpdateJumpRefsOnSessionRename(r.displayName.c_str(), nullptr, inifilename);
                LoadServersFromIniW(inifilenameW, s_quickconnect);
                HWND hTcMain = FindWindowA("TTOTAL_CMD", nullptr);
                if (hTcMain) PostMessage(hTcMain, WM_USER + 51, 540, 0);
                return true;
            }
        }
        return false;
    });
}

BOOL WINAPI FsDeleteFile(LPCSTR RemoteName)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FALSE, [&]() -> BOOL {
        if (!RemoteName || !RemoteName[0])
            return false;
        std::array<WCHAR, wdirtypemax> remoteNameW{};
        return FsDeleteFileW(awlcopy(remoteNameW.data(), RemoteName, remoteNameW.size() - 1));
    });
}

BOOL WINAPI FsRemoveDirW(LPCWSTR RemoteName)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FALSE, [&]() -> BOOL {
        if (!RemoteName || !RemoteName[0])
            return false;
        const PathResolution r = ResolvePathKindW(RemoteName);

        // Real directory inside a session → server-side rmdir.
        if (r.kind == PathKind::SessionWithSubpath) {
            std::wstring remotedir(wdirtypemax, L'\0');
            pConnectSettings serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir.data(), remotedir.size() - 1);
            remotedir.resize(wcslen(remotedir.data()));
            if (serverid == nullptr)
                return false;
            ResetLastPercent(serverid);
            SessionContextGuard _sessionGuard(serverid);
            if (IsLanPairTransport(serverid)) {
                if (!serverid->lanSession || !serverid->lanSession->isConnected()) return false;
                return serverid->lanSession->remove(LanRemotePathToUtf8(remotedir.data()));
            }
            int rc = SftpDeleteFileW(serverid, remotedir.data(), true);
            return (rc == SFTP_OK) ? true : false;
        }

        // Folder grouping → wipe every saved session whose name lives under
        // this folder (recursively — nested subfolders are caught by the same
        // prefix match). TC has already shown the "delete non-empty folder?"
        // confirmation by the time it calls us, so we just do the work.
        if (r.kind == PathKind::Folder && !r.displayName.empty()) {
            // Collect matching section names first; mutating the INI mid-
            // enumeration would shift the underlying buffer.
            std::vector<std::string> toDelete;
            {
                std::array<wchar_t, 65535> serverlist{};
                GetPrivateProfileStringW(nullptr, nullptr, L"", serverlist.data(),
                                          static_cast<DWORD>(serverlist.size()), inifilenameW);
                const std::string needle = r.displayName + "/";
                wchar_t* wp = serverlist.data();
                while (wp[0]) {
                    std::array<char, MAX_PATH> sectionA{};
                    WideCharToMultiByte(CP_ACP, 0, wp, -1, sectionA.data(),
                                         static_cast<int>(sectionA.size()), nullptr, nullptr);
                    const size_t len = strlen(sectionA.data());
                    if (len > needle.size() &&
                        _strnicmp(sectionA.data(), needle.c_str(), needle.size()) == 0) {
                        toDelete.emplace_back(sectionA.data(), len);
                    }
                    wp += wcslen(wp) + 1;
                }
            }

            if (toDelete.empty())
                return false;

            for (const auto& name : toDelete) {
                // Same disconnect-before-delete dance as the single-session
                // path: avoid leaving a ghost entry in the registry.
                std::string disconnPath;
                disconnPath.reserve(name.size() + 1);
                disconnPath.append("\\").append(name);
                FsDisconnect(disconnPath.c_str());
                DeleteServerFromIniW(name.c_str(), inifilenameW);
                if (CryptProc)
                    CryptProc(PluginNumber, CryptoNumber, FS_CRYPT_DELETE_PASSWORD,
                              const_cast<char*>(name.c_str()), nullptr, 0);
                UpdateJumpRefsOnSessionRename(name.c_str(), nullptr, inifilename);
            }

            LoadServersFromIniW(inifilenameW, s_quickconnect);
            HWND hTcMain = FindWindowA("TTOTAL_CMD", nullptr);
            if (hTcMain) PostMessage(hTcMain, WM_USER + 51, 540, 0);
            return true;
        }

        return false;
    });
}

BOOL WINAPI FsRemoveDir(LPCSTR RemoteName)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FALSE, [&]() -> BOOL {
        if (!RemoteName || !RemoteName[0])
            return false;
        std::array<WCHAR, wdirtypemax> remoteNameW{};
        return FsRemoveDirW(awlcopy(remoteNameW.data(), RemoteName, remoteNameW.size() - 1));
    });
}

// ANSI attribute API used by TC in this plugin ABI.

BOOL WINAPI FsSetAttrW(LPCWSTR RemoteName, int NewAttr)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FALSE, [&]() -> BOOL {
        if (!RemoteName || !RemoteName[0])
            return false;
        // Use std::wstring instead of std::array<WCHAR, wdirtypemax>
        std::wstring remotedirW(wdirtypemax, L'\0');
        pConnectSettings serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedirW.data(), remotedirW.size() - 1);
        remotedirW.resize(wcslen(remotedirW.data()));
        if (serverid == nullptr)
            return false;
        ResetLastPercent(serverid);
        SessionContextGuard _sessionGuard(serverid);
        // Use std::string instead of std::array<char, wdirtypemax>
        std::string remotedirA(wdirtypemax, '\0');
        walcopy(remotedirA.data(), remotedirW.data(), remotedirA.size() - 1);
        remotedirA.resize(strlen(remotedirA.data()));
        int rc = SftpSetAttr(serverid, remotedirA.data(), NewAttr);
        return (rc == SFTP_OK) ? true : false;
    });
}

BOOL WINAPI FsSetAttr(LPCSTR RemoteName, int NewAttr)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FALSE, [&]() -> BOOL {
        if (!RemoteName || !RemoteName[0])
            return false;
        std::array<char, wdirtypemax> remotedir{};
        pConnectSettings serverid = GetServerIdAndRelativePathFromPath(RemoteName, remotedir.data(), remotedir.size() - 1);
        if (serverid == nullptr)
            return false;
        ResetLastPercent(serverid);
        int rc = SftpSetAttr(serverid, remotedir.data(), NewAttr);
        return (rc == SFTP_OK) ? true : false;
    });
}

BOOL WINAPI FsSetTimeW(LPCWSTR RemoteName, LPFILETIME CreationTime, LPFILETIME LastAccessTime, LPFILETIME LastWriteTime)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FALSE, [&]() -> BOOL {
        const std::wstring_view remoteView = RemoteName ? std::wstring_view(RemoteName) : std::wstring_view{};
        if (remoteView.size() < 3 || !LastWriteTime)
            return false;

        // Use std::wstring instead of std::array<WCHAR, wdirtypemax>
        std::wstring remotedir(wdirtypemax, L'\0');
        pConnectSettings serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir.data(), remotedir.size() - 1);
        remotedir.resize(wcslen(remotedir.data()));
        if (serverid == nullptr)
            return false;
        ResetLastPercent(serverid);
        int rc = SftpSetDateTimeW(serverid, remotedir.data(), LastWriteTime);
        return (rc == SFTP_OK) ? true : false;
    });
}

BOOL WINAPI FsSetTime(LPCSTR RemoteName, LPFILETIME CreationTime, LPFILETIME LastAccessTime, LPFILETIME LastWriteTime)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FALSE, [&]() -> BOOL {
        if (!RemoteName || !RemoteName[0])
            return false;
        std::array<WCHAR, wdirtypemax> remoteNameW{};
        return FsSetTimeW(awlcopy(remoteNameW.data(), RemoteName, remoteNameW.size() - 1), CreationTime, LastAccessTime, LastWriteTime);
    });
}
