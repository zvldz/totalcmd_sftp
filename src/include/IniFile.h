#pragma once

#include <windows.h>

// Drop-in replacements for the Windows profile API, used for the plugin's
// own INI files (sftpplug.ini, the import cache). Signatures and semantics
// follow GetPrivateProfileString / GetPrivateProfileInt /
// WritePrivateProfileString / GetPrivateProfileSectionNames:
//   * section == nullptr lists section names, key == nullptr lists the keys
//     of a section, as double-null-terminated lists;
//   * value == nullptr deletes the key, key == nullptr deletes the section;
//   * names are case-insensitive, the first match wins;
//   * values are trimmed, one pair of matching surrounding quotes is removed;
//   * truncation and return values match the profile API.
//
// Unlike the profile API the file is kept in UTF-8 (no BOM, CRLF). Reading
// accepts a UTF-8 file (BOM optional), a UTF-16 LE file with BOM, and falls
// back to the system codepage for anything that is not valid UTF-8, so an
// existing ANSI file is read correctly and saved as UTF-8 on its first
// write. Narrow overloads take the plugin's internal strings
// (kInternalCodepage) for sections, keys and values and a CP_ACP path; wide
// ones take UTF-16.
//
// A file in a write-protected folder is looked up and written where Total
// Commander redirects the profile API for plugins:
// %APPDATA%\GHISLER\redirect\<drive>_\<path>. An existing copy there wins;
// a write the original folder refuses creates it.
//
// Parsed files are cached by path and re-read when their timestamp or size
// changes. A write takes a named mutex for the path, re-reads the file if
// another process changed it, applies the change and replaces the file via
// a temporary copy.

DWORD IniGetString(LPCSTR section, LPCSTR key, LPCSTR defaultValue,
                   LPSTR out, DWORD outSize, LPCSTR path);
DWORD IniGetString(LPCWSTR section, LPCWSTR key, LPCWSTR defaultValue,
                   LPWSTR out, DWORD outSize, LPCWSTR path);

UINT IniGetInt(LPCSTR section, LPCSTR key, INT defaultValue, LPCSTR path);
UINT IniGetInt(LPCWSTR section, LPCWSTR key, INT defaultValue, LPCWSTR path);

BOOL IniWriteString(LPCSTR section, LPCSTR key, LPCSTR value, LPCSTR path);
BOOL IniWriteString(LPCWSTR section, LPCWSTR key, LPCWSTR value, LPCWSTR path);

DWORD IniGetSectionNames(LPSTR out, DWORD outSize, LPCSTR path);
DWORD IniGetSectionNames(LPWSTR out, DWORD outSize, LPCWSTR path);

// Reading a file whose path is not in the system codepage (one the user
// dropped on the plugin, say) with internal strings for the rest.
DWORD IniGetString(LPCSTR section, LPCSTR key, LPCSTR defaultValue,
                   LPSTR out, DWORD outSize, LPCWSTR path);
UINT  IniGetInt(LPCSTR section, LPCSTR key, INT defaultValue, LPCWSTR path);
DWORD IniGetSectionNames(LPSTR out, DWORD outSize, LPCWSTR path);
