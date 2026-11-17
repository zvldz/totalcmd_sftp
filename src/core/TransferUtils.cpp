#include "global.h"
#include <windows.h>
#include <array>
#include <string>
#include <vector>
#include <algorithm>
#include "SftpClient.h"
#include "PluginEntryPoints.h"
#include "SftpInternal.h"
#include "IUserFeedback.h"
#include "CoreUtils.h"
#include "UnicodeHelpers.h"
#include "TransferUtils.h"
#include "TextConversion.h"
#include "WildcardMatch.h"

int GetPercent(int64_t offset, int64_t filesize)
{
    if (filesize <= 0)
        return 0;
    const int percent = static_cast<int>((offset * 100) / filesize);
    return std::clamp(percent, 0, 100);
}

bool IsValidFileHandle(HANDLE hf) noexcept
{
    return hf != nullptr && hf != INVALID_HANDLE_VALUE;
}

bool AskUserYesNo(pConnectSettings cs, LPCSTR title, LPCSTR message)
{
    if (cs && cs->feedback)
        return cs->feedback->AskYesNo(message ? message : "", title ? title : "SFTP");
    return RequestProcI(PluginNumber, RT_MsgYesNo, title ? title : "SFTP", message ? message : "", nullptr, 0) != 0;
}

std::string ToRemotePathA(pConnectSettings cs, LPCWSTR pathW)
{
    std::array<char, wdirtypemax> tmp{};
    CopyRemotePathW2A(cs, pathW, tmp.data(), tmp.size());
    return std::string(tmp.data());
}

std::string BuildShellScpArgument(const std::string& path)
{
    return "'" + string_util::ShellQuoteSingle(path) + "'";
}

bool SftpDetermineTransferModeW(LPCWSTR RemoteName)
{
    std::lock_guard<std::mutex> lock(g_transferModeMutex);
    if (Global_TransferMode == 'A')
        return true;
    if (Global_TransferMode == 'I')
        return false;

    // Auto mode: check extension against Global_TextTypes
    std::wstring_view name(RemoteName);
    const auto slash = name.find_last_of(L"/\\");
    if (slash != std::wstring_view::npos)
        name.remove_prefix(slash + 1);

    return MultiFileMatchW(Global_TextTypes.data(), name.data());
}

bool MeasureTextUpload(HANDLE file, int64_t& convertedSize)
{
    convertedSize = 0;
    LARGE_INTEGER zero{};
    if (!SetFilePointerEx(file, zero, nullptr, FILE_BEGIN))
        return false;

    text_conversion::CrLfToLf counter;
    std::vector<char> buf(256 * 1024);
    bool isText = true;
    for (;;) {
        DWORD got = 0;
        // A read error is reported by the upload's own read; sending the file
        // unconverted keeps the announced size equal to what is read.
        if (!ReadFile(file, buf.data(), static_cast<DWORD>(buf.size()), &got, nullptr)) {
            isText = false;
            break;
        }
        if (got == 0)
            break;
        if (std::find(buf.data(), buf.data() + got, '\0') != buf.data() + got) {
            isText = false;
            break;
        }
        convertedSize += static_cast<int64_t>(counter.Count(buf.data(), got));
    }
    convertedSize += static_cast<int64_t>(counter.FinishCount());
    SetFilePointerEx(file, zero, nullptr, FILE_BEGIN);
    return isText;
}
