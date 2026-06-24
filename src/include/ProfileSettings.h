#pragma once
#include "SftpClient.h"

bool LoadProxySettingsFromNr(int proxynr, pConnectSettings ConnectResults, LPCSTR iniFileName);
bool LoadServerSettings(LPCSTR DisplayName, pConnectSettings ConnectResults, LPCSTR iniFileName);

// Walk every section in the INI, locate any `jumpsessionref` value that
// exactly matches `oldName` (case-insensitive), and rewrite it to `newName`.
// If `newName` is null or empty, the key is removed instead — used when a
// referenced session is being deleted. Critical for keeping jump-host
// references intact across session/folder rename + delete operations.
void UpdateJumpRefsOnSessionRename(LPCSTR oldName, LPCSTR newName, LPCSTR iniFileName);

// Prefix variant for bulk folder renames: any `jumpsessionref` value that
// starts with `oldPrefix + "/"` has that prefix swapped for `newPrefix + "/"`.
// Used by F6 on a folder to keep jump references valid after every session
// under the folder has been renamed.
void UpdateJumpRefsOnFolderRename(LPCSTR oldPrefix, LPCSTR newPrefix, LPCSTR iniFileName);
