#include "RemoteNames.h"

#include <libssh2/libssh2.h>
#include <libssh2/libssh2_sftp.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>

DWORD ParseLsMode(const std::string& perms)
{
    if (perms.size() < 10)
        return 0;
    DWORD mode = 0;
    switch (perms[0]) {
        case 'd': mode = LIBSSH2_SFTP_S_IFDIR;  break;
        case 'l': mode = LIBSSH2_SFTP_S_IFLNK;  break;
        case 'b': mode = LIBSSH2_SFTP_S_IFBLK;  break;
        case 'c': mode = LIBSSH2_SFTP_S_IFCHR;  break;
        case 'p': mode = LIBSSH2_SFTP_S_IFIFO;  break;
        case 's': mode = LIBSSH2_SFTP_S_IFSOCK; break;
        default:  mode = LIBSSH2_SFTP_S_IFREG;  break;
    }
    static constexpr DWORD kBits[9] = { 0400, 0200, 0100, 040, 020, 010, 04, 02, 01 };
    for (int i = 0; i < 9; ++i) {
        const char c = perms[1 + i];
        if (c != '-' && c != 'S' && c != 'T')
            mode |= kBits[i];
    }
    if (perms[3] == 's' || perms[3] == 'S') mode |= 04000;
    if (perms[6] == 's' || perms[6] == 'S') mode |= 02000;
    if (perms[9] == 't' || perms[9] == 'T') mode |= 01000;
    return mode;
}

bool ParseLsDate(const std::string& mon, const std::string& day,
                 const std::string& timeOrYear, FILETIME& ft)
{
    static constexpr const char* kMonths[12] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    WORD month = 0;
    for (WORD i = 0; i < 12; ++i) {
        if (_stricmp(mon.c_str(), kMonths[i]) == 0) {
            month = i + 1;
            break;
        }
    }
    const int d = atoi(day.c_str());
    if (month == 0 || d < 1 || d > 31)
        return false;

    SYSTEMTIME st{};
    st.wMonth = month;
    st.wDay   = static_cast<WORD>(d);
    int hh = 0, mm = 0;
    if (sscanf_s(timeOrYear.c_str(), "%d:%d", &hh, &mm) == 2) {
        if (hh < 0 || hh > 23 || mm < 0 || mm > 59)
            return false;
        SYSTEMTIME now{};
        GetSystemTime(&now);
        st.wYear   = now.wYear;
        st.wHour   = static_cast<WORD>(hh);
        st.wMinute = static_cast<WORD>(mm);
        FILETIME nowFt{};
        SystemTimeToFileTime(&now, &nowFt);
        auto ticks = [](const FILETIME& f) {
            return (static_cast<ULONGLONG>(f.dwHighDateTime) << 32) | f.dwLowDateTime;
        };
        constexpr ULONGLONG kOneDay100ns = 24ULL * 60 * 60 * 10000000;
        if (SystemTimeToFileTime(&st, &ft) && ticks(ft) > ticks(nowFt) + kOneDay100ns)
            --st.wYear;
    } else {
        const int year = atoi(timeOrYear.c_str());
        if (year < 1601 || year > 9999)
            return false;
        st.wYear = static_cast<WORD>(year);
    }
    return SystemTimeToFileTime(&st, &ft) != 0;
}

bool ShellCommandIsSafe(std::string_view command) noexcept
{
    for (const char ch : command) {
        const unsigned char c = static_cast<unsigned char>(ch);
        if ((c < 0x20 && c != '\n') || c == 0x7F)
            return false;
    }
    return true;
}

std::string BaseNameFromPath(const std::string& path)
{
    if (path.empty())
        return "upload.bin";
    std::string normalized;
    bool quoted = false;
    for (size_t i = 0; i < path.size(); ++i) {
        const char c = path[i];
        if (c == '\'') {
            quoted = !quoted;
        } else if (!quoted && c == '\\' && i + 1 < path.size()) {
            normalized.push_back(path[++i]);
        } else {
            normalized.push_back(c);
        }
    }
    size_t pos = normalized.find_last_of('/');
    if (pos == std::string::npos || pos + 1 >= normalized.size())
        return normalized;
    return normalized.substr(pos + 1);
}

void SanitizeLocalFileNameW(LPWSTR localPath) noexcept
{
    if (!localPath || !localPath[0])
        return;
    const std::wstring_view pathView(localPath);
    const size_t slashPos = pathView.find_last_of(L"\\/");
    if (slashPos == std::wstring_view::npos || slashPos + 1 >= pathView.size())
        return;
    wchar_t* const name = localPath + slashPos + 1;
    for (wchar_t* p = name; *p; ++p) {
        if (static_cast<unsigned>(*p) < 32u || wcschr(L"<>:\"|?*\\/", *p))
            *p = L'_';
    }
    const size_t len = wcslen(name);
    if (len > 0 && (name[len - 1] == L'.' || name[len - 1] == L' '))
        name[len - 1] = L'_';

    size_t baseLen = wcscspn(name, L".");
    while (baseLen > 0 && name[baseLen - 1] == L' ')
        --baseLen;
    const std::wstring_view base(name, baseLen);
    auto is = [&](const wchar_t* dev) {
        return base.size() == wcslen(dev) && _wcsnicmp(base.data(), dev, base.size()) == 0;
    };
    bool device = is(L"CON") || is(L"PRN") || is(L"AUX") || is(L"NUL") || is(L"CONIN$") || is(L"CONOUT$");
    if (!device && base.size() == 4 && base[3] >= L'1' && base[3] <= L'9')
        device = _wcsnicmp(base.data(), L"COM", 3) == 0 || _wcsnicmp(base.data(), L"LPT", 3) == 0;
    if (device)
        name[baseLen - 1] = L'_';
}
