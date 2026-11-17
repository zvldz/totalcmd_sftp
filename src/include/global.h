#pragma once

// Modern C++ SFTP Plugin for Total Commander
// Compatible with Visual Studio 2026 (v145 toolset)

#define WIN32_LEAN_AND_MEAN

// Force static linking for libssh2 (removes __imp__ prefix)
#ifndef LIBSSH2_STATIC
    #define LIBSSH2_STATIC
#endif

/* Disable legacy WinSock.h and wsock32.lib */
#define _WINSOCKAPI_

// Modern Windows SDK headers
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <BaseTsd.h>
#include <stdlib.h>
#include <stdio.h>
#include <shlwapi.h>
#include <strsafe.h>

// C++ Standard Library headers
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <cstdarg>

// Verify SDK requirements
#ifndef RESOURCE_ENUM_VALIDATE
#error "Please, update Microsoft SDKs to 6.1 or later"
#endif

// Type definitions for compatibility
#ifndef _LPCBYTE_DEFINED
#define _LPCBYTE_DEFINED
typedef const BYTE *LPCBYTE;
#endif

#ifndef _LPCVOID_DEFINED
#define _LPCVOID_DEFINED
typedef const VOID *LPCVOID;
#endif

// Modern replacement for countof macro
#ifndef countof
#define countof(array) (sizeof(array) / sizeof(array[0]))
#endif

// Modern C++ namespace for plugin internals
#ifdef __cplusplus

#include "fsplugin.h"

// Modern type aliases
using PluginId = int;
using ServerId = void*;
using ServerHandle = void*;

// Constant for directory path buffers
constexpr size_t wdirtypemax = 1024;

// ============================================================================
// Logging Configuration
// ============================================================================
// Set LOG_TO_FILE to 1 to enable file logging, 0 to disable.
// When enabled, output goes to LOG_FILE_NAME in the user's temporary folder
// (%TEMP%), which only that user can read or write.
// OutputDebugString is always used when logging is active.
// WARNING: File logging is slow — enable only during active investigation.
// A stable release is built with LOG_ENABLED 0; the release workflow refuses
// a stable tag otherwise.

// A build can override it (cl /DLOG_ENABLED=0): CI builds and tests the
// stable configuration that way on every tag, before a stable one exists.
#ifndef LOG_ENABLED
#define LOG_ENABLED  1                              // Master switch: 0 = off, 1 = on
#endif
#define LOG_TO_FILE  1                            // 0 = OutputDebugString only, 1 = + file
#define LOG_FILE_NAME L"sftpplug.log"              // File name inside %TEMP%

// Internal aliases — do not edit below this line.
#define SFTP_DEBUG_ENABLED  LOG_ENABLED
#define SFTP_DEBUG_TO_FILE  LOG_TO_FILE
#define SFTP_DEBUG_LEVEL    (LOG_ENABLED ? 2 : 0)

#if SFTP_DEBUG_ENABLED
inline void sftp_debug_emit_line(const char* line) noexcept
{
    if (!line) return;
    OutputDebugStringA(line);
    OutputDebugStringA("\n");
#if SFTP_DEBUG_TO_FILE
    wchar_t logPath[MAX_PATH + 32] = {};
    const DWORD n = GetTempPathW(MAX_PATH + 1, logPath);
    if (n == 0 || n > MAX_PATH)
        return;
    wcsncat_s(logPath, LOG_FILE_NAME, _TRUNCATE);

    // Shared for writing: background transfers log at the same time, and an
    // append-only handle adds each line whole at the end. Past 20 MB the log
    // moves to sftpplug.log.old and starts again.
    const DWORD share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    HANDLE hf = CreateFileW(logPath, FILE_APPEND_DATA, share, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER size{};
        if (GetFileSizeEx(hf, &size) && size.QuadPart > 20LL * 1024 * 1024) {
            CloseHandle(hf);
            wchar_t oldPath[MAX_PATH + 40] = {};
            wcsncpy_s(oldPath, logPath, _TRUNCATE);
            wcsncat_s(oldPath, L".old", _TRUNCATE);
            MoveFileExW(logPath, oldPath, MOVEFILE_REPLACE_EXISTING);
            hf = CreateFileW(logPath, FILE_APPEND_DATA, share, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hf == INVALID_HANDLE_VALUE)
                return;
        }
        // One write per line, so lines of two threads never interleave.
        char buf[1100];
        const size_t len = strlen(line);
        DWORD written = 0;
        if (len + 2 <= sizeof(buf)) {
            memcpy(buf, line, len);
            buf[len] = '\r';
            buf[len + 1] = '\n';
            WriteFile(hf, buf, static_cast<DWORD>(len + 2), &written, nullptr);
        } else {
            WriteFile(hf, line, static_cast<DWORD>(len), &written, nullptr);
            WriteFile(hf, "\r\n", 2, &written, nullptr);
        }
        CloseHandle(hf);
    }
#endif
}

inline void sftp_debug_logf(const char* tag, const char* fmt, ...) noexcept
{
    char msg[1024];
    msg[0] = 0;
    va_list args;
    va_start(args, fmt);
    _vsnprintf_s(msg, sizeof(msg), _TRUNCATE, fmt ? fmt : "", args);
    va_end(args);

    // Local time to the millisecond, so a slow step shows as a gap between lines.
    SYSTEMTIME st;
    GetLocalTime(&st);
    char line[1200];
    if (tag && tag[0]) {
        _snprintf_s(line, sizeof(line), _TRUNCATE, "%02u:%02u:%02u.%03u [%s] %s",
                    st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, tag, msg);
    } else {
        _snprintf_s(line, sizeof(line), _TRUNCATE, "%02u:%02u:%02u.%03u %s",
                    st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, msg);
    }
    sftp_debug_emit_line(line);
}

    #define SFTP_LOG(tag, fmt, ...) do { \
        sftp_debug_logf(tag, fmt, ##__VA_ARGS__); \
    } while(0)
    #define DEBUG_LOG(fmt, ...) SFTP_LOG("DBG", fmt, ##__VA_ARGS__)
    #define ENABLE_SCP_DEBUG
#else
    #define SFTP_LOG(tag, fmt, ...) do {} while(0)
    #define DEBUG_LOG(fmt, ...) do {} while(0)
#endif

// Inline helper for safe string operations
namespace detail {
    template<typename T, size_t N>
    constexpr size_t array_size(T (&)[N]) noexcept { return N; }
}

#endif // __cplusplus

