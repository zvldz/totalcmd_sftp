// Plugin functions the tested sources call but whose own files would pull in
// the whole plugin. Same contract as the plugin's versions.

#include <windows.h>
#include <string>
#include <string_view>
#include "fsplugin.h"

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

// Total Commander's callbacks are never set: the wrappers that call them
// check for null and do nothing.
tProgressProc  ProgressProc  = nullptr;
tProgressProcW ProgressProcW = nullptr;
tLogProc       LogProc       = nullptr;
tLogProcW      LogProcW      = nullptr;
tRequestProc   RequestProc   = nullptr;
tRequestProcW  RequestProcW  = nullptr;

// The registry tests never connect, so nothing is ever closed.
struct tConnectSettings;
DWORD mainthreadid = 0;

int SftpCloseConnection(tConnectSettings*)
{
    return 0;
}
