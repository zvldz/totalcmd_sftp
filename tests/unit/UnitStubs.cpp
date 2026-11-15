// Plugin functions the tested sources call but whose own files would pull in
// the whole plugin. Same contract as the plugin's versions.

#include <windows.h>
#include <string>
#include <string_view>

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
