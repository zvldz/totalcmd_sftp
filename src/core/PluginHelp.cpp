#include "global.h"
#include <windows.h>
#include <shellapi.h>
#include <array>
#include <string>
#include <vector>
#include "SftpClient.h"
#include "PluginEntryPoints.h"
#include "WindowsUserFeedback.h"
#include "res/resource.h"
#include "CoreUtils.h"
#include "UnicodeHelpers.h"

#pragma comment(lib, "version.lib")

// Reads FileVersion from own VERSIONINFO resource, returns e.g. "1.0.0.10"
// Returns empty string on failure.
std::wstring GetPluginVersionW()
{
    std::array<wchar_t, MAX_PATH> path{};
    if (!GetModuleFileNameW(hinst, path.data(), static_cast<DWORD>(path.size())))
        return {};

    DWORD dummy{};
    const DWORD size = GetFileVersionInfoSizeW(path.data(), &dummy);
    if (!size)
        return {};

    std::vector<BYTE> buf(size);
    if (!GetFileVersionInfoW(path.data(), 0, size, buf.data()))
        return {};

    VS_FIXEDFILEINFO* pvi{};
    UINT len{};
    if (!VerQueryValueW(buf.data(), L"\\", reinterpret_cast<void**>(&pvi), &len) || !pvi)
        return {};

    wchar_t ver[32]{};
    swprintf_s(ver, L"%u.%u.%u.%u",
        HIWORD(pvi->dwFileVersionMS),
        LOWORD(pvi->dwFileVersionMS),
        HIWORD(pvi->dwFileVersionLS),
        LOWORD(pvi->dwFileVersionLS));
    return ver;
}

bool GetPluginDirectoryU8(std::string& outDir)
{
    outDir.clear();
    std::vector<wchar_t> dllPath(32768);
    const DWORD n = GetModuleFileNameW(hinst, dllPath.data(), static_cast<DWORD>(dllPath.size()));
    if (n == 0 || n >= dllPath.size())
        return false;
    const std::wstring_view path(dllPath.data(), n);
    const size_t slash = path.find_last_of(L'\\');
    if (slash == std::wstring_view::npos || slash == 0)
        return false;
    outDir = unicode_util::wstring_to_utf8(path.substr(0, slash));
    return !outDir.empty();
}

void OpenPluginHelp(HWND hWnd)
{
    std::string pluginDir;
    WindowsUserFeedback feedback(hWnd);
    if (!GetPluginDirectoryU8(pluginDir)) {
        feedback.ShowError(LngStrU8(IDS_ERR_NO_PLUGIN_DIR, "Cannot locate plugin directory."), "Help");
        return;
    }

    // Build title with version: "SFTP Plugin v1.0.0.10"
    std::wstring helpTitle = L"SFTP Plugin";
    const std::wstring ver = GetPluginVersionW();
    if (!ver.empty())
        helpTitle += L" v" + ver;
#if SFTP_EXTRA
    helpTitle += L" extra";
#endif

    // One self-contained page, opened by whatever handles .html. It replaced
    // a CHM: the only compiler for that format was withdrawn, and a CHM
    // arriving inside a downloaded ZIP is blocked by Windows and opens blank.
    const std::wstring pluginDirW = unicode_util::utf8_to_wstring(pluginDir);
    const std::wstring helpPathW = pluginDirW + L"\\SFTPplug-help.html";
    DWORD attrs = GetFileAttributesW(helpPathW.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0) {
        HINSTANCE openRc = ShellExecuteW(hWnd, L"open", helpPathW.c_str(), nullptr, pluginDirW.c_str(), SW_SHOWNORMAL);
        if (reinterpret_cast<INT_PTR>(openRc) > 32)
            return;
    }

    // Nothing to open: fall back to the same block the F7 row shows, so the
    // user still gets the essentials.
    const std::wstring shortHelpW =
        unicode_util::utf8_to_wstring(LngStrU8(IDS_HELPTEXT, "Plugin help:"));
    std::wstring msgW = L"Help file not found or failed to open.\n\nExpected location:\n";
    msgW += helpPathW;
    msgW += L"\n\n";
    msgW += shortHelpW;
    feedback.ShowError(unicode_util::wide_to_internal(msgW), unicode_util::wide_to_internal(helpTitle));
}
