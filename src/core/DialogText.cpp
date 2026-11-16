#include "global.h"
#include <windows.h>
#include <array>
#include <span>
#include <string>
#include "DialogText.h"
#include "LngLoader.h"
#include "PluginEntryPoints.h"

std::wstring LoadResStringW(UINT id)
{
    if (const char* lngStr = LngGetString(id)) {
        const int len = MultiByteToWideChar(CP_UTF8, 0, lngStr, -1, nullptr, 0);
        if (len <= 0)
            return {};
        std::wstring out(static_cast<size_t>(len - 1), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, lngStr, -1, out.data(), len);
        return out;
    }
    // Read in place: a zero buffer size makes LoadStringW return a pointer
    // to the resource, so a string of any length comes whole.
    const wchar_t* res = nullptr;
    const int n = LoadStringW(hinst, id, reinterpret_cast<LPWSTR>(&res), 0);
    return (n > 0 && res) ? std::wstring(res, static_cast<size_t>(n)) : std::wstring();
}

void LocalizeDlgControls(HWND hDlg, UINT captionId, std::span<const DialogString> controls)
{
    if (const std::wstring caption = LoadResStringW(captionId); !caption.empty())
        SetWindowTextW(hDlg, caption.c_str());
    for (const auto& c : controls) {
        if (const std::wstring text = LoadResStringW(c.string); !text.empty())
            SetDlgItemTextW(hDlg, c.control, text.c_str());
    }
}
