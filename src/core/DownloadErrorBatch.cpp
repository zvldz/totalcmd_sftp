#include "global.h"
#include <windows.h>
#include <array>
#include <string>
#include "DownloadErrorBatch.h"
#include "fsplugin.h"
#include "LngLoader.h"
#include "PluginEntryPoints.h"
#include "UnicodeHelpers.h"
#include "res/resource.h"

namespace {

thread_local unsigned t_batchDepth = 0;
thread_local bool t_skipAll = false;

// The string for id from the .lng file or the resources; empty if neither has it.
std::wstring ResString(UINT id)
{
    std::array<WCHAR, 512> buf{};
    if (!LngLoadStringW(hinst, id, buf.data(), static_cast<int>(buf.size())))
        return {};
    return buf.data();
}

void SetResText(HWND hWnd, UINT id)
{
    const std::wstring text = ResString(id);
    if (!text.empty())
        SetWindowTextW(hWnd, text.c_str());
}

INT_PTR CALLBACK DownloadErrorDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_INITDIALOG:
        SetResText(hDlg, IDS_DOWNLOAD_ERROR_TITLE);
        SetResText(GetDlgItem(hDlg, IDC_DOWNLOAD_ERROR_TEXT), IDS_DOWNLOAD_ERROR_TEXT);
        SetResText(GetDlgItem(hDlg, IDC_DOWNLOAD_SKIP), IDS_DOWNLOAD_SKIP);
        SetResText(GetDlgItem(hDlg, IDC_DOWNLOAD_SKIP_ALL), IDS_DOWNLOAD_SKIP_ALL);
        SetDlgItemTextW(hDlg, IDC_DOWNLOAD_ERROR_PATH, reinterpret_cast<LPCWSTR>(lParam));
        // Focus on Skip, so the read-only path does not open selected.
        SetFocus(GetDlgItem(hDlg, IDC_DOWNLOAD_SKIP));
        return FALSE;
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_DOWNLOAD_SKIP:
        case IDC_DOWNLOAD_SKIP_ALL:
        case IDCANCEL:
            EndDialog(hDlg, LOWORD(wParam));
            return TRUE;
        default:
            break;
        }
        break;
    default:
        break;
    }
    return FALSE;
}

// The window the question belongs to: the transfer's own progress window when
// this thread has one, Total Commander's main window otherwise.
HWND QuestionOwner() noexcept
{
    if (HWND active = GetActiveWindow())
        return GetAncestor(active, GA_ROOTOWNER);
    return FindWindowW(L"TTOTAL_CMD", nullptr);
}

INT_PTR AskUser(LPCWSTR remoteName)
{
    return DialogBoxParamW(hinst, MAKEINTRESOURCEW(IDD_DOWNLOAD_ERROR), QuestionOwner(),
                           DownloadErrorDlgProc, reinterpret_cast<LPARAM>(remoteName ? remoteName : L""));
}

void LogSkipped(LPCWSTR remoteName)
{
    std::wstring line = ResString(IDS_LOG_DOWNLOAD_SKIPPED);
    if (line.empty())
        line = L"Skipped after a download error:";
    line += L' ';
    line += remoteName ? remoteName : L"";
    LogProcI(PluginNumber, MSGTYPE_IMPORTANTERROR, unicode_util::wide_to_internal(line).c_str());
}

} // namespace

namespace download_batch {

void Begin() noexcept
{
    if (t_batchDepth++ == 0)
        t_skipAll = false;
}

void End() noexcept
{
    if (t_batchDepth > 0 && --t_batchDepth == 0)
        t_skipAll = false;
}

int ResolveReadError(LPCWSTR remoteName, LPCWSTR localName, bool move, bool resume)
{
    if (move || resume || t_batchDepth == 0) {
        SFTP_LOG("ENTRY", "Download error, not offered a skip (move=%d resume=%d batch=%u)",
                 move ? 1 : 0, resume ? 1 : 0, t_batchDepth);
        return FS_FILE_READERROR;
    }

    if (t_skipAll) {
        SFTP_LOG("ENTRY", "Download error, skipped (skip all)");
    } else {
        switch (AskUser(remoteName)) {
        case IDC_DOWNLOAD_SKIP:
            SFTP_LOG("ENTRY", "Download error, skipped");
            break;
        case IDC_DOWNLOAD_SKIP_ALL:
            SFTP_LOG("ENTRY", "Download error, skipped, and skip all from now on");
            t_skipAll = true;
            break;
        case IDCANCEL:
            SFTP_LOG("ENTRY", "Download error, copy cancelled");
            return FS_FILE_USERABORT;
        default: // the question could not be shown: the plain error stands
            SFTP_LOG("ENTRY", "Download error, the question could not be shown");
            return FS_FILE_READERROR;
        }
    }

    // A skipped file leaves nothing behind that could pass for a download.
    if (localName && localName[0] && !DeleteFileT(localName)) {
        const DWORD error = GetLastError();
        if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND)
            return FS_FILE_WRITEERROR;
    }
    LogSkipped(remoteName);
    return FS_FILE_OK;
}

} // namespace download_batch
