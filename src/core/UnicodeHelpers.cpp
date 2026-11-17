// UnicodeHelpers.cpp - ANSI/UTF-8/UTF-16 conversion, TC callback wrappers,
// file operations with long path support.

#include "UnicodeHelpers.h"
#include "shellapi.h"

#include <string>
#include <algorithm>
#include <climits>
#include <cstring>
#include <cwchar>
#include <array>

// External callback functions (defined in PluginEntryPoints.cpp)
extern tProgressProcW ProgressProcW;
extern tLogProcW      LogProcW;
extern tRequestProcW  RequestProcW;
extern tProgressProc  ProgressProc;
extern tLogProc       LogProc;
extern tRequestProc   RequestProc;

// ============================================================================
// String Conversion Functions
// ============================================================================

LPWSTR wcslcpy(LPWSTR str1, LPCWSTR str2, size_t imaxlen) noexcept
{
    if (!str1 || !str2 || imaxlen == 0) return str1;

    size_t i = 0;
    const size_t limit = imaxlen - 1;
    while (i < limit && str2[i]) {
        str1[i] = str2[i];
        ++i;
    }
    str1[i] = L'\0';
    return str1;
}

LPWSTR wcslcat(LPWSTR str1, LPCWSTR str2, size_t imaxlen) noexcept
{
    if (!str1 || !str2 || imaxlen == 0) return str1;

    // Clamp existing length to the declared destination capacity.
    size_t len1 = 0;
    while (len1 < imaxlen && str1[len1]) {
        ++len1;
    }
    if (len1 >= imaxlen) {
        str1[imaxlen - 1] = L'\0';
        return str1;
    }

    size_t i = 0;
    const size_t limit = imaxlen - len1 - 1;
    while (i < limit && str2[i]) {
        str1[len1 + i] = str2[i];
        ++i;
    }
    str1[len1 + i] = L'\0';
    return str1;
}

LPSTR walcopy(LPSTR outname, LPCWSTR inname, size_t maxlen) noexcept
{
    return walcopyCP(CP_ACP, outname, inname, maxlen);
}

LPSTR walcopyCP(int codepage, LPSTR outname, LPCWSTR inname, size_t maxlen) noexcept
{
    if (!outname || !inname || maxlen == 0) return nullptr;

    outname[0] = '\0';
    const int result = WideCharToMultiByte(codepage, 0, inname, -1, outname, static_cast<int>(maxlen), nullptr, nullptr);
    if (result > 0 && static_cast<size_t>(result) <= maxlen) {
        outname[result - 1] = '\0';
    } else if (maxlen > 0) {
        outname[maxlen - 1] = '\0';
    }
    return outname;
}

LPWSTR awlcopy(LPWSTR outname, LPCSTR inname, size_t maxlen) noexcept
{
    return awlcopyCP(CP_ACP, outname, inname, maxlen);
}

LPWSTR awlcopyCP(int codepage, LPWSTR outname, LPCSTR inname, size_t maxlen) noexcept
{
    if (!outname || !inname || maxlen == 0) return nullptr;

    outname[0] = L'\0';
    const int result = MultiByteToWideChar(codepage, 0, inname, -1, outname, static_cast<int>(maxlen));
    if (result > 0 && static_cast<size_t>(result) <= maxlen) {
        outname[result - 1] = L'\0';
    } else if (maxlen > 0) {
        outname[maxlen - 1] = L'\0';
    }
    return outname;
}

// UTF-8 <-> UTF-16 through the system converter, which validates its input
// and turns every invalid sequence into U+FFFD. Both write at most
// outmax - 1 units, never split a multi-byte character or a surrogate pair,
// always terminate when asked to, and return the units written - or -1 when
// the input was cut short to fit.
int ConvUTF16toUTF8(LPCWSTR inbuf, size_t inlen, LPSTR outbuf, size_t outmax, bool nullterm) noexcept
{
    if (!inbuf || !outbuf || outmax < 2) return -1;
    if (nullterm) outbuf[0] = '\0';
    if (inlen == 0) inlen = wcslen(inbuf);
    if (inlen == 0) return 0;
    if (inlen > INT_MAX) return -1;

    const int need = WideCharToMultiByte(CP_UTF8, 0, inbuf, static_cast<int>(inlen), nullptr, 0, nullptr, nullptr);
    if (need <= 0) return -1;
    try {
        std::string utf8(static_cast<size_t>(need), '\0');
        WideCharToMultiByte(CP_UTF8, 0, inbuf, static_cast<int>(inlen), utf8.data(), need, nullptr, nullptr);
        size_t n = utf8.size();
        const bool truncated = n > outmax - 1;
        if (truncated) {
            n = outmax - 1;
            while (n > 0 && (static_cast<unsigned char>(utf8[n]) & 0xC0) == 0x80)
                --n; // utf8[n] continues the character that started before it
        }
        memcpy(outbuf, utf8.data(), n);
        if (nullterm) outbuf[n] = '\0';
        return truncated ? -1 : static_cast<int>(n);
    } catch (...) {
        return -1;
    }
}

int ConvUTF8toUTF16(LPCSTR inbuf, size_t inlen, LPWSTR outbuf, size_t outmax, bool nullterm) noexcept
{
    if (!inbuf || !outbuf || outmax < 2) return -1;
    if (nullterm) outbuf[0] = L'\0';
    if (inlen == 0) inlen = strlen(inbuf);
    if (inlen == 0) return 0;
    if (inlen > INT_MAX) return -1;

    const int need = MultiByteToWideChar(CP_UTF8, 0, inbuf, static_cast<int>(inlen), nullptr, 0);
    if (need <= 0) return -1;
    try {
        std::wstring utf16(static_cast<size_t>(need), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, inbuf, static_cast<int>(inlen), utf16.data(), need);
        size_t n = utf16.size();
        const bool truncated = n > outmax - 1;
        if (truncated) {
            n = outmax - 1;
            if (n > 0 && IS_HIGH_SURROGATE(utf16[n - 1]))
                --n;
        }
        memcpy(outbuf, utf16.data(), n * sizeof(wchar_t));
        if (nullterm) outbuf[n] = L'\0';
        return truncated ? -1 : static_cast<int>(n);
    } catch (...) {
        return -1;
    }
}

// ============================================================================
// Internal Helper Functions
// ============================================================================

namespace {

// A path the long-path API takes: past 248 characters (where creating a
// folder already fails) an absolute one gets the \\?\ prefix, \\?\UNC\ for a
// network path, after being made full — with the prefix Windows no longer
// resolves '/' or "..". A path that has a prefix, or is relative, stays as
// it is. False when the result does not fit `maxlen`.
[[nodiscard]] bool MakeExtraLongNameW(LPWSTR outbuf, LPCWSTR inbuf, size_t maxlen) noexcept
{
    if (!outbuf || !inbuf || maxlen == 0) return false;
    outbuf[0] = L'\0';

    const size_t inLen = wcslen(inbuf);
    const bool prefixed = wcsncmp(inbuf, L"\\\\?\\", 4) == 0 || wcsncmp(inbuf, L"\\\\.\\", 4) == 0;
    const bool absolute = (inLen >= 3 && inbuf[1] == L':' && (inbuf[2] == L'\\' || inbuf[2] == L'/')) ||
                          (inLen >= 2 && inbuf[0] == L'\\' && inbuf[1] == L'\\');
    if (inLen < 248 || prefixed || !absolute) {
        if (inLen + 1 > maxlen) return false;
        wcscpy_s(outbuf, maxlen, inbuf);
        return true;
    }
    try {
        const DWORD need = GetFullPathNameW(inbuf, 0, nullptr, nullptr);
        if (need == 0) return false;
        std::wstring full(need, L'\0');
        const DWORD len = GetFullPathNameW(inbuf, need, full.data(), nullptr);
        if (len == 0 || len >= need) return false;
        full.resize(len);
        std::wstring out = full.rfind(L"\\\\", 0) == 0
            ? L"\\\\?\\UNC\\" + full.substr(2)
            : L"\\\\?\\" + full;
        if (out.size() + 1 > maxlen) return false;
        wcscpy_s(outbuf, maxlen, out.c_str());
        return true;
    } catch (...) {
        return false;
    }
}

} // anonymous namespace

// ============================================================================
// FIND_DATA Conversion Functions
// ============================================================================

void copyfinddatawa(LPWIN32_FIND_DATA lpFindFileDataA, LPWIN32_FIND_DATAW lpFindFileDataW) noexcept
{
    if (!lpFindFileDataA || !lpFindFileDataW) return;
    
    // Convert WCHAR arrays to CHAR arrays
    for (size_t i = 0; i < _countof(lpFindFileDataA->cFileName) - 1 && i < _countof(lpFindFileDataW->cFileName); ++i) {
        lpFindFileDataA->cFileName[i] = static_cast<char>(lpFindFileDataW->cFileName[i] & 0xFF);
    }
    lpFindFileDataA->cFileName[_countof(lpFindFileDataA->cFileName) - 1] = '\0';
    
    for (size_t i = 0; i < _countof(lpFindFileDataA->cAlternateFileName) - 1 && i < _countof(lpFindFileDataW->cAlternateFileName); ++i) {
        lpFindFileDataA->cAlternateFileName[i] = static_cast<char>(lpFindFileDataW->cAlternateFileName[i] & 0xFF);
    }
    lpFindFileDataA->cAlternateFileName[_countof(lpFindFileDataA->cAlternateFileName) - 1] = '\0';
    
    lpFindFileDataA->dwFileAttributes = lpFindFileDataW->dwFileAttributes;
    lpFindFileDataA->ftCreationTime = lpFindFileDataW->ftCreationTime;
    lpFindFileDataA->ftLastAccessTime = lpFindFileDataW->ftLastAccessTime;
    lpFindFileDataA->ftLastWriteTime = lpFindFileDataW->ftLastWriteTime;
    lpFindFileDataA->nFileSizeHigh = lpFindFileDataW->nFileSizeHigh;
    lpFindFileDataA->nFileSizeLow = lpFindFileDataW->nFileSizeLow;
    lpFindFileDataA->dwReserved0 = lpFindFileDataW->dwReserved0;
    lpFindFileDataA->dwReserved1 = lpFindFileDataW->dwReserved1;
}

void copyfinddataaw(LPWIN32_FIND_DATAW lpFindFileDataW, LPWIN32_FIND_DATA lpFindFileDataA) noexcept
{
    if (!lpFindFileDataW || !lpFindFileDataA) return;
    
    // Convert CHAR arrays to WCHAR arrays
    for (size_t i = 0; i < _countof(lpFindFileDataW->cFileName) - 1 && i < _countof(lpFindFileDataA->cFileName); ++i) {
        lpFindFileDataW->cFileName[i] = static_cast<wchar_t>(static_cast<unsigned char>(lpFindFileDataA->cFileName[i]));
    }
    lpFindFileDataW->cFileName[_countof(lpFindFileDataW->cFileName) - 1] = L'\0';
    
    for (size_t i = 0; i < _countof(lpFindFileDataW->cAlternateFileName) - 1 && i < _countof(lpFindFileDataA->cAlternateFileName); ++i) {
        lpFindFileDataW->cAlternateFileName[i] = static_cast<wchar_t>(static_cast<unsigned char>(lpFindFileDataA->cAlternateFileName[i]));
    }
    lpFindFileDataW->cAlternateFileName[_countof(lpFindFileDataW->cAlternateFileName) - 1] = L'\0';
    
    lpFindFileDataW->dwFileAttributes = lpFindFileDataA->dwFileAttributes;
    lpFindFileDataW->ftCreationTime = lpFindFileDataA->ftCreationTime;
    lpFindFileDataW->ftLastAccessTime = lpFindFileDataA->ftLastAccessTime;
    lpFindFileDataW->ftLastWriteTime = lpFindFileDataA->ftLastWriteTime;
    lpFindFileDataW->nFileSizeHigh = lpFindFileDataA->nFileSizeHigh;
    lpFindFileDataW->nFileSizeLow = lpFindFileDataA->nFileSizeLow;
    lpFindFileDataW->dwReserved0 = lpFindFileDataA->dwReserved0;
    lpFindFileDataW->dwReserved1 = lpFindFileDataA->dwReserved1;
}

// ============================================================================
// Callback Proxy Functions
// ============================================================================

int ProgressProcT(int PluginNr, LPCWSTR SourceName, LPCWSTR TargetName, int PercentDone) noexcept
{
    if (ProgressProcW) {
        return ProgressProcW(PluginNr, SourceName, TargetName, PercentDone);
    }
    return 0;
}

void LogProcT(int PluginNr, int MsgType, LPCWSTR LogString) noexcept
{
    if (LogProcW) {
        LogProcW(PluginNr, MsgType, LogString);
    } else if (LogProc) {
        try {
            LogProc(PluginNr, MsgType,
                    unicode_util::wide_to_narrow(LogString ? LogString : L"", CP_ACP).c_str());
        } catch (...) {
        }
    }
}

// Internal-string forms of the three callbacks: the wide callback when Total
// Commander supplied one, otherwise the ANSI one in the system codepage.
namespace {

std::string InternalToAcp(LPCSTR s)
{
    return unicode_util::wide_to_narrow(unicode_util::internal_to_wide(s ? s : ""), CP_ACP);
}

std::string AcpToInternal(LPCSTR s)
{
    return unicode_util::wide_to_internal(unicode_util::narrow_to_wide(s ? s : "", CP_ACP));
}

} // namespace

int ProgressProcI(int PluginNr, LPCSTR SourceName, LPCSTR TargetName, int PercentDone) noexcept
{
    try {
        if (ProgressProcW) {
            const std::wstring src = unicode_util::internal_to_wide(SourceName ? SourceName : "");
            const std::wstring dst = unicode_util::internal_to_wide(TargetName ? TargetName : "");
            return ProgressProcW(PluginNr, SourceName ? src.c_str() : nullptr,
                                 TargetName ? dst.c_str() : nullptr, PercentDone);
        }
        if (ProgressProc) {
            const std::string src = InternalToAcp(SourceName);
            const std::string dst = InternalToAcp(TargetName);
            return ProgressProc(PluginNr, SourceName ? src.c_str() : nullptr,
                                TargetName ? dst.c_str() : nullptr, PercentDone);
        }
    } catch (...) {
    }
    return 0;
}

void LogProcI(int PluginNr, int MsgType, LPCSTR LogString) noexcept
{
    try {
        if (LogProcW)
            LogProcW(PluginNr, MsgType, unicode_util::internal_to_wide(LogString ? LogString : "").c_str());
        else if (LogProc)
            LogProc(PluginNr, MsgType, InternalToAcp(LogString).c_str());
    } catch (...) {
    }
}

// `ReturnedText` comes in with the default answer and goes out with the
// user's, both internal strings of at most `maxlen` characters.
BOOL RequestProcI(int PluginNr, int RequestType, LPCSTR CustomTitle, LPCSTR CustomText,
                  LPSTR ReturnedText, int maxlen) noexcept
{
    try {
        if (RequestProcW) {
            const std::wstring title = unicode_util::internal_to_wide(CustomTitle ? CustomTitle : "");
            const std::wstring text  = unicode_util::internal_to_wide(CustomText ? CustomText : "");
            std::wstring answer;
            if (ReturnedText && maxlen > 0) {
                answer = unicode_util::internal_to_wide(ReturnedText);
                answer.resize(static_cast<size_t>(maxlen) + 1, L'\0');
            }
            const BOOL ok = RequestProcW(PluginNr, RequestType,
                                         CustomTitle ? title.c_str() : nullptr,
                                         CustomText ? text.c_str() : nullptr,
                                         ReturnedText && maxlen > 0 ? answer.data() : nullptr, maxlen);
            if (ok && ReturnedText && maxlen > 0)
                (void)wilcopy(ReturnedText, answer.c_str(), static_cast<size_t>(maxlen));
            SecureZeroMemory(answer.data(), answer.size() * sizeof(wchar_t));
            return ok;
        }
        if (RequestProc) {
            const std::string title = InternalToAcp(CustomTitle);
            const std::string text  = InternalToAcp(CustomText);
            std::string answer;
            if (ReturnedText && maxlen > 0) {
                answer = InternalToAcp(ReturnedText);
                answer.resize(static_cast<size_t>(maxlen) + 1, '\0');
            }
            const BOOL ok = RequestProc(PluginNr, RequestType,
                                        CustomTitle ? title.c_str() : nullptr,
                                        CustomText ? text.c_str() : nullptr,
                                        ReturnedText && maxlen > 0 ? answer.data() : nullptr, maxlen);
            if (ok && ReturnedText && maxlen > 0) {
                const std::string back = AcpToInternal(answer.c_str());
                strncpy_s(ReturnedText, static_cast<size_t>(maxlen), back.c_str(), _TRUNCATE);
            }
            SecureZeroMemory(answer.data(), answer.size());
            return ok;
        }
    } catch (...) {
    }
    return FALSE;
}

BOOL SetDlgItemTextI(HWND hDlg, int nIDDlgItem, LPCSTR lpString) noexcept
{
    try {
        return SetDlgItemTextW(hDlg, nIDDlgItem,
                               unicode_util::internal_to_wide(lpString ? lpString : "").c_str());
    } catch (...) {
        return FALSE;
    }
}

UINT GetDlgItemTextI(HWND hDlg, int nIDDlgItem, LPSTR lpString, int cchMax) noexcept
{
    if (!lpString || cchMax <= 0)
        return 0;
    lpString[0] = 0;
    try {
        const HWND ctrl = GetDlgItem(hDlg, nIDDlgItem);
        const int wlen = ctrl ? GetWindowTextLengthW(ctrl) : 0;
        std::wstring w(static_cast<size_t>(wlen) + 1, L'\0');
        const int got = GetDlgItemTextW(hDlg, nIDDlgItem, w.data(), wlen + 1);
        w.resize(static_cast<size_t>(got > 0 ? got : 0));
        (void)wilcopy(lpString, w.c_str(), static_cast<size_t>(cchMax));
        SecureZeroMemory(w.data(), w.size() * sizeof(wchar_t));
        return static_cast<UINT>(strlen(lpString));
    } catch (...) {
        return 0;
    }
}

// ============================================================================
// File Operations with Long Path Support
// ============================================================================

BOOL CreateDirectoryT(LPCWSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes) noexcept
{
    if (!lpPathName) return FALSE;
    
    std::array<WCHAR, wdirtypemax> wbuf{};
    if (!MakeExtraLongNameW(wbuf.data(), lpPathName, wbuf.size() - 1)) {
        return FALSE;
    }
    
    return CreateDirectoryW(wbuf.data(), lpSecurityAttributes);
}

BOOL RemoveDirectoryT(LPCWSTR lpPathName) noexcept
{
    if (!lpPathName) return FALSE;
    
    std::array<WCHAR, wdirtypemax> wbuf{};
    if (!MakeExtraLongNameW(wbuf.data(), lpPathName, wbuf.size() - 1)) {
        return FALSE;
    }
    
    return RemoveDirectoryW(wbuf.data());
}

BOOL DeleteFileT(LPCWSTR lpFileName) noexcept
{
    if (!lpFileName) return FALSE;
    
    std::array<WCHAR, wdirtypemax> wbuf{};
    if (!MakeExtraLongNameW(wbuf.data(), lpFileName, wbuf.size() - 1)) {
        return FALSE;
    }
    
    return DeleteFileW(wbuf.data());
}

BOOL MoveFileT(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName) noexcept
{
    if (!lpExistingFileName || !lpNewFileName) return FALSE;
    
    std::array<WCHAR, wdirtypemax> wbuf1{};
    if (!MakeExtraLongNameW(wbuf1.data(), lpExistingFileName, wbuf1.size() - 1)) {
        return FALSE;
    }
    
    std::array<WCHAR, wdirtypemax> wbuf2{};
    if (!MakeExtraLongNameW(wbuf2.data(), lpNewFileName, wbuf2.size() - 1)) {
        return FALSE;
    }
    
    return MoveFileW(wbuf1.data(), wbuf2.data());
}

BOOL SetFileAttributesT(LPCWSTR lpFileName, DWORD dwFileAttributes) noexcept
{
    if (!lpFileName) return FALSE;
    
    std::array<WCHAR, wdirtypemax> wbuf{};
    if (!MakeExtraLongNameW(wbuf.data(), lpFileName, wbuf.size() - 1)) {
        return FALSE;
    }
    
    return SetFileAttributesW(wbuf.data(), dwFileAttributes);
}

DWORD GetFileAttributesT(LPCWSTR lpFileName) noexcept
{
    if (!lpFileName) return INVALID_FILE_ATTRIBUTES;

    std::array<WCHAR, wdirtypemax> wbuf{};
    if (!MakeExtraLongNameW(wbuf.data(), lpFileName, wbuf.size() - 1)) {
        return INVALID_FILE_ATTRIBUTES;
    }

    return GetFileAttributesW(wbuf.data());
}

HANDLE CreateFileT(
    LPCWSTR lpFileName, 
    DWORD dwDesiredAccess, 
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes, 
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, 
    HANDLE hTemplateFile) noexcept
{
    if (!lpFileName) return INVALID_HANDLE_VALUE;
    
    std::array<WCHAR, wdirtypemax> wbuf{};
    if (!MakeExtraLongNameW(wbuf.data(), lpFileName, wbuf.size() - 1)) {
        return INVALID_HANDLE_VALUE;
    }
    
    return CreateFileW(wbuf.data(), dwDesiredAccess, dwShareMode, lpSecurityAttributes, 
                       dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

HANDLE FindFirstFileT(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData) noexcept
{
    if (!lpFileName || !lpFindFileData) return INVALID_HANDLE_VALUE;
    
    std::array<WCHAR, wdirtypemax> wbuf{};
    if (!MakeExtraLongNameW(wbuf.data(), lpFileName, wbuf.size() - 1)) {
        return INVALID_HANDLE_VALUE;
    }
    
    return FindFirstFileW(wbuf.data(), lpFindFileData);
}

BOOL FindNextFileT(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData) noexcept
{
    if (!hFindFile || !lpFindFileData) return FALSE;

    return FindNextFileW(hFindFile, lpFindFileData);
}

// ============================================================================
// Modern C++20 String Helpers - implementation
// ============================================================================

namespace unicode_util {

std::string wide_to_narrow(std::wstring_view w, int codepage)
{
    if (w.empty()) {
        return {};
    }
    const int len = WideCharToMultiByte(codepage, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    if (len <= 0) {
        return {};
    }
    std::string result(len, '\0');
    WideCharToMultiByte(codepage, 0, w.data(), static_cast<int>(w.size()), result.data(), len, nullptr, nullptr);
    return result;
}

std::wstring narrow_to_wide(std::string_view a, int codepage)
{
    if (a.empty()) {
        return {};
    }
    const int len = MultiByteToWideChar(codepage, 0, a.data(), static_cast<int>(a.size()), nullptr, 0);
    if (len <= 0) {
        return {};
    }
    std::wstring result(len, L'\0');
    MultiByteToWideChar(codepage, 0, a.data(), static_cast<int>(a.size()), result.data(), len);
    return result;
}

std::wstring utf8_to_wstring(std::string_view utf8)
{
    return narrow_to_wide(utf8, CP_UTF8);
}

std::string wstring_to_utf8(std::wstring_view wstr)
{
    return wide_to_narrow(wstr, CP_UTF8);
}

} // namespace unicode_util
