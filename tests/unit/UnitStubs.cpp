// Plugin functions the tested sources call but whose own files would pull in
// the whole plugin. Same contract as the plugin's versions.

#include <windows.h>
#include <string>
#include <string_view>
#include "fsplugin.h"

namespace unicode_util {

std::wstring narrow_to_wide(std::string_view a, int codepage)
{
    if (a.empty())
        return {};
    const int n = MultiByteToWideChar(static_cast<UINT>(codepage), 0, a.data(), static_cast<int>(a.size()), nullptr, 0);
    if (n <= 0)
        return {};
    std::wstring w(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(static_cast<UINT>(codepage), 0, a.data(), static_cast<int>(a.size()), w.data(), n);
    return w;
}

} // namespace unicode_util

// No Total Commander here, so no password store either.
bool HaveCryptProc() noexcept
{
    return false;
}

int  PluginNumber   = 0;
int  CryptoNumber   = 0;
bool CryptCheckPass = false;

int CryptProcI(int, int, int, LPCSTR, LPSTR, int) noexcept
{
    return FS_FILE_NOTSUPPORTED;
}

extern "C" LPSTR strlcpy(LPSTR p, LPCSTR p2, size_t maxlen)
{
    if (!p || !maxlen)
        return p;
    size_t i = 0;
    for (; p2 && p2[i] && i < maxlen - 1; ++i)
        p[i] = p2[i];
    p[i] = '\0';
    return p;
}
