#pragma once
#include "SftpClient.h"

#include <string>
#include <vector>

bool LoadProxySettingsFromNr(int proxynr, pConnectSettings ConnectResults, LPCSTR iniFileName);
bool LoadServerSettings(LPCSTR DisplayName, pConnectSettings ConnectResults, LPCSTR iniFileName);

// Copy every profile field LoadServerSettings reads, leaving identity
// (DisplayName / IniFileName), live connection state and runtime flags alone.
//
// The connection dialog needs this when the user picks a different session:
// its controls are refilled from the newly loaded profile, but OK saves from
// the settings object, and the settings object still describes the session
// selected before. Fields with no control of their own — the jump host, PHP
// and LAN-pair options, the auto-detect tri-states — would otherwise be
// written over the newly selected session, silently replacing its
// configuration with the previous one's.
//
// Keep this in step with LoadServerSettings: a profile field added there and
// missed here causes exactly that data loss.
void AssignProfileFields(pConnectSettings dst, const tConnectSettings& src);

// Put the profile fields back to what a session that the INI says nothing
// about would have. The connection dialog needs this for its "new session"
// entry, which names no profile to load: without it the dialog keeps showing,
// and OK keeps saving, the session selected before it.
//
// The values here are the defaults LoadServerSettings passes to
// GetPrivateProfile*, and have to stay in step with them.
void ResetProfileFields(pConnectSettings dst);

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
