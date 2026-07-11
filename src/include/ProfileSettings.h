#pragma once
#include "SftpClient.h"

#include <string>
#include <vector>

bool LoadProxySettingsFromNr(int proxynr, pConnectSettings ConnectResults, LPCSTR iniFileName);
bool LoadServerSettings(LPCSTR DisplayName, pConnectSettings ConnectResults, LPCSTR iniFileName);

// Read / write the per-source list of user-added custom scan paths. Storage
// lives in the plugin's own sftpplug.ini under the [Imports] section, with
// one key per source: "<sourceId>.custom_paths=path1;path2;...". Semicolons
// are the separator; paths that contain a literal `;` are not supported yet
// (documented gap — none of the target OSes place `;` in normal folder
// names). Empty list means the source has no custom paths configured.
//
// LoadImportCustomPaths reads the ";"-joined list and returns the split
// vector (empty if key absent). SaveImportCustomPath appends `path` if not
// already present (case-insensitive dedup). RemoveImportCustomPath drops
// `path` from the list if present.
std::vector<std::string> LoadImportCustomPaths(LPCSTR sourceId, LPCSTR iniFileName);
bool SaveImportCustomPath  (LPCSTR sourceId, LPCSTR path, LPCSTR iniFileName);
bool RemoveImportCustomPath(LPCSTR sourceId, LPCSTR path, LPCSTR iniFileName);

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
