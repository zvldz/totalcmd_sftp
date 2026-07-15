#pragma once

#include <windows.h>

#include <functional>
#include <string>

namespace sftp {

// Return true if `iniPath` holds a section named `section` with a non-empty
// `server` or `user` key. Used to detect collision when materialising a
// virtual/imported session into the plugin's own sftpplug.ini, and to answer
// the same "does this saved session exist?" question for adapters whose
// import flow needs to pick a unique name.
bool IniSectionExists(const std::string& section, LPCSTR iniPath) noexcept;

// Callback invoked once per regular file discovered under `root`.
//   fullPath  absolute path (backslash-joined).
//   relPath   path relative to `root`, joined with '/', without the file
//             extension — ready to use as a DisplayName segment (e.g.
//             "team/aws/prod").
// Return `true` to continue walking, `false` to stop.
using WalkFileCallback = std::function<bool(const std::wstring& fullPath,
                                             const std::string& relPath)>;

// Recursively enumerate `root`. Every regular file whose extension matches
// `ext` (case-insensitive, without a leading dot; empty ⇒ any) is passed to
// `onFile`. Symlinks and directories are traversed but never reported.
void WalkDirectoryFiles(const std::wstring& root,
                        const std::wstring& ext,
                        WalkFileCallback     onFile);

// Modern shell folder picker. `title` and `initialPath` are ANSI (CP_ACP);
// the returned `outPath` is ANSI. Returns false if the user cancelled or the
// selection could not be resolved to a filesystem path (e.g. namespace-only).
bool BrowseForFolder(HWND               owner,
                     const char*        title,
                     const char*        initialPath,
                     std::string&       outPath);

// Single-file picker via GetOpenFileNameW. `filter` is a NUL-separated Win32
// filter string ("Session files\0*.reg\0All files\0*.*\0"); the terminating
// double-NUL is required. `initialPath` may be a full file path (splits into
// directory + name) or a bare directory. Returns false on cancel.
bool BrowseForFile(HWND               owner,
                   const char*        title,
                   const char*        filter,
                   const char*        initialPath,
                   std::string&       outPath);

// Parse a PuTTY-style `LineCodePage` value ("UTF-8", "KOI8-R", "ISO-8859-2",
// "CP1251", "WIN-1252", "Windows-1250", …) into the two-field representation
// the plugin's INI uses: `outUtf8` is 0 or 1 (feeds `utf8=` INI key), and
// `outCodepage` is a numeric Windows codepage (feeds `codepage=`). When both
// come back as their default (0, 0) with the function returning false the
// value is either empty or unrecognised — caller should leave existing
// settings untouched. `outUtf8=1` implies `outCodepage=0`; the two are
// mutually exclusive by contract.
//
// Portable across adapters — PuTTY and WinSCP both write `LineCodePage`
// entries with the same alphabet, and both new adapters (PuttyAdapter,
// WinScpAdapter) call this to reach feature parity with wesmar's legacy
// F11 import.
bool ParseLineCodePage(const std::string& raw,
                       int& outUtf8, int& outCodepage) noexcept;

}  // namespace sftp
