#pragma once

#include <windows.h>
#include <string>
#include <string_view>

// Names and listing columns as a remote shell prints them, and the local
// names they become. No connection is involved: the plugin's parsing alone.

// Full st_mode from the `drwxr-xr-x` column: file type plus permission bits,
// with s/S and t/T as setuid/setgid/sticky (upper case: execute not set).
// 0 for a column shorter than ten characters.
DWORD ParseLsMode(const std::string& perms);

// Date columns of `ls -la` run with LC_TIME=C and TZ=UTC0: "Mon DD HH:MM" for
// recent files, "Mon DD YYYY" for older ones. A time without a year that
// lands more than a day ahead belongs to last year.
bool ParseLsDate(const std::string& mon, const std::string& day,
                 const std::string& timeOrYear, FILETIME& ft);

// Whether a command can go to the interactive shell: no control character
// other than a newline, which a terminal would act on rather than pass.
bool ShellCommandIsSafe(std::string_view command) noexcept;

// The file name from a path argument as BuildShellScpArgument quotes it:
// single quotes, with each quote inside written as '\''.
std::string BaseNameFromPath(const std::string& path);

// The local file name for a remote one, made something Windows stores under
// that name. A character Windows does not allow becomes '_'; so does a dot
// or space at the end, which Windows would drop ("report." onto "report");
// and a device name ("nul", "con.txt", "com1"), which would send the data
// nowhere and let a move delete the source, gets its last letter replaced.
// Only the part after the last separator is changed, in place, so the name
// keeps its length.
void SanitizeLocalFileNameW(LPWSTR localPath) noexcept;
