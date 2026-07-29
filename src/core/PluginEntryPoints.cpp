// sertransplg.cpp : Defines the entry point for the DLL application.
// Total Commander SFTP filesystem plugin entry points.
// Maintainer: Marek Wesolowski (wesmar)

#include <winsock2.h>
#include <windows.h>
#include <shellapi.h>
#include <stdlib.h>
#include <array>
#include <memory>
#include <string>
#include <string_view>
#include <algorithm>
#include "fsplugin.h"
#include "BuildInfo.h"
#include "CoreUtils.h"
#include "res/resource.h"
#include "SftpClient.h"
#include "SftpInternal.h"
#include "ServerRegistry.h"
#include "UnicodeHelpers.h"
#include "PluginEntryPoints.h"
#include "DllExceptionBarrier.h"
#include "LanPairSession.h"
#include "LngLoader.h"
#include "PhpAgentClient.h"
#include "PluginEntryPointsInternal.h"
#include "ImportCache.h"
#include "VirtualSessionRegistry.h"

// Declared in SftpConnection.cpp
void StartGlobalLanServices(bool startServer = true);
void StopGlobalLanServices();

HINSTANCE hinst = nullptr;
HWND hWndMain = nullptr;

#define defininame  "sftpplug.ini"
#define defininamew L"sftpplug.ini"
#define templatefile "sftpplug.tpl"
char    inifilename[MAX_PATH]  = defininame;   // ANSI path (legacy / read-only)
wchar_t inifilenameW[MAX_PATH] = defininamew;  // Unicode path (preferred for all ini calls)
char g_wincmdIniPath[MAX_PATH] = {};    // path to wincmd.ini, used for live language detection
char pluginname[] = "SFTP";
char defrootname[] = "Secure FTP";

char s_f7newconnection[32];
char s_quickconnect[64];
std::array<WCHAR, 32> s_f7newconnectionW{};
std::array<WCHAR, 32> s_quickconnectW{};

bool disablereading = false;   // disable reading of subdirs to delete whole drives
bool g_inMultiOpTransfer = false;  // see header for purpose
bool freportconnect = true;    // report connect to caller only on first connect
bool CryptCheckPass = false;   // check 'store password encrypted' by default

int PluginNumber = 0;
int CryptoNumber = 0;
DWORD mainthreadid = 0;
tProgressProc  ProgressProc = nullptr;
tProgressProcW ProgressProcW = nullptr;
tLogProc       LogProc = nullptr;
tLogProcW      LogProcW = nullptr;
tRequestProc   RequestProc = nullptr;
tRequestProcW  RequestProcW = nullptr;
tCryptProc     CryptProc = nullptr;
static bool g_winsockInitialized = false;
static LANGID g_configuredUiLangId = 0;

static LANGID DetectTcUiLangIdFromIni(const char* tcIniPath) noexcept
{
    if (!tcIniPath || !tcIniPath[0]) {
        return 0;
    }

    std::array<char, MAX_PATH> expandedIniPath{};
    const DWORD expanded = ExpandEnvironmentStringsA(tcIniPath, expandedIniPath.data(),
                                                     static_cast<DWORD>(expandedIniPath.size()));
    const char* iniPath = tcIniPath;
    if (expanded > 0 && expanded < expandedIniPath.size()) {
        iniPath = expandedIniPath.data();
    }

    std::array<char, MAX_PATH> languageIni{};
    GetPrivateProfileStringA("Configuration", "LanguageIni", "", languageIni.data(),
                             static_cast<DWORD>(languageIni.size()), iniPath);
    if (!languageIni[0]) {
        return 0;
    }

    // Normalize to uppercase to make matching robust across naming conventions.
    CharUpperBuffA(languageIni.data(), static_cast<DWORD>(strlen(languageIni.data())));
    std::string normalized(languageIni.data());

    auto has = [&normalized](const char* token) noexcept -> bool {
        return normalized.find(token) != std::string::npos;
    };

    // Common TC naming patterns:
    // - WCMD_PL.LNG / WCMD_POL.LNG
    // - WCMD_DE.LNG / WCMD_DEU.LNG
    // - WCMD_FR.LNG / WCMD_FRA.LNG
    // - WCMD_ES.LNG / WCMD_ESP.LNG
    // - WCMD_IT.LNG / WCMD_ITA.LNG
    // - WCMD_RU.LNG  / WCMD_RUS.LNG
    // - WCMD_CZ.LNG / WCMD_CSY.LNG
    // - WCMD_HU.LNG / WCMD_HUN.LNG
    // - WCMD_JP.LNG / WCMD_JPN.LNG
    // - WCMD_NL.LNG / WCMD_NLD.LNG
    // - WCMD_BR.LNG / WCMD_PTB.LNG
    // - WCMD_RO.LNG / WCMD_ROM.LNG
    // - WCMD_SK.LNG / WCMD_SKY.LNG
    // - WCMD_UA.LNG / WCMD_UKR.LNG
    // - WCMD_SC.LNG / WCMD_CHS.LNG
    if (has("_PL") || has(".PL") || has("POL")) {
        return MAKELANGID(LANG_POLISH, SUBLANG_DEFAULT);
    }
    if (has("_DE") || has(".DE") || has("DEU") || has("GER")) {
        return MAKELANGID(LANG_GERMAN, SUBLANG_GERMAN);
    }
    if (has("_FR") || has(".FR") || has("FRA") || has("FRE")) {
        return MAKELANGID(LANG_FRENCH, SUBLANG_FRENCH);
    }
    if (has("_ES") || has(".ES") || has("ESP") || has("SPA")) {
        return MAKELANGID(LANG_SPANISH, SUBLANG_SPANISH_MODERN);
    }
    if (has("_IT") || has(".IT") || has("ITA")) {
        return MAKELANGID(LANG_ITALIAN, SUBLANG_ITALIAN);
    }
    if (has("_RU") || has(".RU") || has("RUS")) {
        return MAKELANGID(LANG_RUSSIAN, SUBLANG_DEFAULT);
    }
    if (has("_CZ") || has(".CZ") || has("CSY") || has("_CS")) {
        return MAKELANGID(LANG_CZECH, SUBLANG_DEFAULT);
    }
    if (has("_HU") || has(".HU") || has("HUN")) {
        return MAKELANGID(LANG_HUNGARIAN, SUBLANG_DEFAULT);
    }
    if (has("_JP") || has(".JP") || has("JPN")) {
        return MAKELANGID(LANG_JAPANESE, SUBLANG_DEFAULT);
    }
    if (has("_NL") || has(".NL") || has("NLD") || has("HOL")) {
        return MAKELANGID(LANG_DUTCH, SUBLANG_DUTCH);
    }
    if (has("_BR") || has("PTB") || has("PT-B")) {
        return MAKELANGID(LANG_PORTUGUESE, SUBLANG_PORTUGUESE_BRAZILIAN);
    }
    if (has("_RO") || has(".RO") || has("ROM") || has("RUM")) {
        return MAKELANGID(LANG_ROMANIAN, SUBLANG_DEFAULT);
    }
    if (has("_SK") || has(".SK") || has("SKY")) {
        return MAKELANGID(LANG_SLOVAK, SUBLANG_DEFAULT);
    }
    if (has("_UA") || has(".UA") || has("UKR") || has("_UK")) {
        return MAKELANGID(LANG_UKRAINIAN, SUBLANG_DEFAULT);
    }
    if (has("_SC") || has("_CN") || has("CHS") || has("CHI") || has("CHN")) {
        return MAKELANGID(LANG_CHINESE, SUBLANG_CHINESE_SIMPLIFIED);
    }
    if (has("_EN") || has(".EN") || has("ENU") || has("ENG")) {
        return MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US);
    }

    return 0;
}

static void ApplyLangId(LANGID langId) noexcept
{
    g_configuredUiLangId = langId;

    // Load external .lng file (clears any previous load; English has no .lng file).
    LngLoadForLanguage(langId, hinst);

    SetThreadUILanguage(langId);
    SetThreadLocale(MAKELCID(langId, SORT_DEFAULT));

    // Refresh cached strings: prefer .lng translation, fall back to compiled RC resource.
    const char* f7Str = LngGetString(IDS_F7NEW);
    if (f7Str) {
        std::wstring wF7 = unicode_util::utf8_to_wstring(f7Str);
        wcsncpy_s(s_f7newconnectionW.data(), s_f7newconnectionW.size(), wF7.c_str(), _TRUNCATE);
    } else {
        LoadStringW(hinst, IDS_F7NEW, s_f7newconnectionW.data(), static_cast<int>(s_f7newconnectionW.size()) - 1);
    }
    walcopy(s_f7newconnection, s_f7newconnectionW.data(), countof(s_f7newconnection) - 1);

    const char* qcStr = LngGetString(IDS_QUICKCONNECT);
    if (qcStr) {
        std::wstring wQc = unicode_util::utf8_to_wstring(qcStr);
        wcsncpy_s(s_quickconnectW.data(), s_quickconnectW.size(), wQc.c_str(), _TRUNCATE);
    } else {
        LoadStringW(hinst, IDS_QUICKCONNECT, s_quickconnectW.data(), static_cast<int>(s_quickconnectW.size()) - 1);
    }
    walcopy(s_quickconnect, s_quickconnectW.data(), countof(s_quickconnect) - 1);
}

static LANGID LangNameToId(const wchar_t* name) noexcept
{
    std::string s;
    for (const wchar_t* p = name; *p; ++p)
        s += static_cast<char>(towlower(*p));

    if (s == "english"    || s == "en"    || s == "enu")  return MAKELANGID(LANG_ENGLISH,    SUBLANG_ENGLISH_US);
    if (s == "polish"     || s == "pol"   || s == "pl")   return MAKELANGID(LANG_POLISH,     SUBLANG_DEFAULT);
    if (s == "german"     || s == "deu"   || s == "de")   return MAKELANGID(LANG_GERMAN,     SUBLANG_GERMAN);
    if (s == "french"     || s == "fra"   || s == "fr")   return MAKELANGID(LANG_FRENCH,     SUBLANG_FRENCH);
    if (s == "spanish"    || s == "esp"   || s == "es")   return MAKELANGID(LANG_SPANISH,    SUBLANG_SPANISH_MODERN);
    if (s == "italian"    || s == "ita"   || s == "it")   return MAKELANGID(LANG_ITALIAN,    SUBLANG_ITALIAN);
    if (s == "russian"    || s == "rus"   || s == "ru")   return MAKELANGID(LANG_RUSSIAN,    SUBLANG_DEFAULT);
    if (s == "czech"      || s == "cs")                   return MAKELANGID(LANG_CZECH,      SUBLANG_DEFAULT);
    if (s == "hungarian"  || s == "hu")                   return MAKELANGID(LANG_HUNGARIAN,  SUBLANG_DEFAULT);
    if (s == "japanese"   || s == "ja")                   return MAKELANGID(LANG_JAPANESE,   SUBLANG_DEFAULT);
    if (s == "dutch"      || s == "nl")                   return MAKELANGID(LANG_DUTCH,      SUBLANG_DUTCH);
    if (s == "portuguese" || s == "pt-br" || s == "ptb")  return MAKELANGID(LANG_PORTUGUESE, SUBLANG_PORTUGUESE_BRAZILIAN);
    if (s == "romanian"   || s == "ro")                   return MAKELANGID(LANG_ROMANIAN,   SUBLANG_DEFAULT);
    if (s == "slovak"     || s == "sk")                   return MAKELANGID(LANG_SLOVAK,     SUBLANG_DEFAULT);
    if (s == "ukrainian"  || s == "uk")                   return MAKELANGID(LANG_UKRAINIAN,  SUBLANG_DEFAULT);
    if (s == "chinese"    || s == "zh-cn" || s == "chs")  return MAKELANGID(LANG_CHINESE,    SUBLANG_CHINESE_SIMPLIFIED);
    return 0;
}

void ApplyTcLanguageToPluginResources(const char* tcIniPath) noexcept
{
    LANGID langId = DetectTcUiLangIdFromIni(tcIniPath);

    // No match means TC runs a language this plugin ships no .lng for.
    // Fall back to English rather than leaving an earlier translation in
    // place: ApplyLangId -> LngLoadForLanguage -> LangIdToTcCode returns
    // nullptr for English, which clears the translation map so strings
    // come from the compiled resources.
    if (langId == 0)
        langId = MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US);

    ApplyLangId(langId);
}

void ApplyConfiguredUiLanguageForCurrentThread() noexcept
{
    if (g_configuredUiLangId == 0) {
        return;
    }
    SetThreadUILanguage(g_configuredUiLangId);
    SetThreadLocale(MAKELCID(g_configuredUiLangId, SORT_DEFAULT));
}

LANGID GetConfiguredUiLanguageId() noexcept
{
    return g_configuredUiLangId;
}


BOOL APIENTRY DllMain( HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        hinst = (HINSTANCE)hModule;
        // Top-level SEH filter for native crashes (AV, stack overflow, etc.)
        // that bypass DllExceptionBarrier. Installed first so it's active for
        // the whole DLL lifetime.
        sftp::InstallCrashHandler();
        LoadStringW(hinst, IDS_F7NEW, s_f7newconnectionW.data(), static_cast<int>(s_f7newconnectionW.size()) - 1);
        walcopy(s_f7newconnection, s_f7newconnectionW.data(), countof(s_f7newconnection) - 1);
        LoadStringW(hinst, IDS_QUICKCONNECT, s_quickconnectW.data(), static_cast<int>(s_quickconnectW.size()) - 1);
        walcopy(s_quickconnect, s_quickconnectW.data(), countof(s_quickconnect) - 1);
    }
    if (ul_reason_for_call == DLL_PROCESS_DETACH) {
        // Stop LAN services before CRT destroys global objects
        StopGlobalLanServices();
        ShutdownMultiServer();
        if (g_winsockInitialized) {
            WSACleanup();
            g_winsockInitialized = false;
        }
        // Restore previous SEH filter before releasing DbgHelp symbol tables.
        sftp::UninstallCrashHandler();
        // Release DbgHelp symbol tables — required for clean reload
        sftp::ShutdownSymbols();
    }
    return true;
}

// Returns true when operation should be aborted by user/progress callback.
static bool MessageLoop(pConnectSettings ConnectSettings) noexcept
{
    bool aborted = false;
    if (ConnectSettings && get_ticks_between(ConnectSettings->lastpercenttime) > PROGRESS_UPDATE_MS) {
        // Keep this call after soft_aborted is set.
        // Prefer the Unicode variant (set by FsInitW); fall back to ANSI (set by FsInit).
        WCHAR* src = ConnectSettings->current_sourceW[0] ? ConnectSettings->current_sourceW : nullptr;
        WCHAR* dst = ConnectSettings->current_targetW[0] ? ConnectSettings->current_targetW : nullptr;

        if (ProgressProcW)
            aborted = (0 != ProgressProcW(PluginNumber, src, dst, ConnectSettings->lastpercent));
        else if (ProgressProc) {
            std::array<char, wdirtypemax> srcA{}, dstA{};
            if (src) walcopyCP(ConnectSettings->codepage, srcA.data(), src, srcA.size()-1);
            if (dst) walcopyCP(ConnectSettings->codepage, dstA.data(), dst, dstA.size()-1);
            aborted = (0 != ProgressProc(PluginNumber, src ? srcA.data() : nullptr, dst ? dstA.data() : nullptr, ConnectSettings->lastpercent));
        }
        // Allow cancellation with Escape when no progress dialog is shown.
        ConnectSettings->lastpercenttime = get_sys_ticks();
    }
    return aborted;
}

void LogMsg(LPCSTR fmt, ...) noexcept
{
    std::array<char, 512> buf{};
    va_list argptr;
    va_start(argptr, fmt);
    int len = _vsnprintf(buf.data(), buf.size() - 2, fmt, argptr);
    va_end(argptr);
    if (len < 0) {
        strcpy_s(buf.data(), buf.size(), "<INCORRECT-INPUT-DATA> ");
        strcat_s(buf.data(), buf.size(), fmt);
    } else {
        buf[static_cast<size_t>(len)] = 0;
    }
    LogProc(PluginNumber, MSGTYPE_DETAILS, buf.data());
}

// Thread-local "current session" for ShowStatus prefix. Set via
// SessionContextGuard at Fs*-entry points; nullptr otherwise.
namespace {
thread_local const tConnectSettings* g_currentSession = nullptr;

// Pick the user-recognisable identifier for the session.
// Preference order: saved name (DisplayName) → server/host → empty.
std::string SessionPrefixA(const tConnectSettings* cs)
{
    if (!cs) return {};
    const std::string& name = !cs->DisplayName.empty() ? cs->DisplayName : cs->server;
    if (name.empty()) return {};
    std::string out;
    out.reserve(name.size() + 3);
    out.append("[").append(name).append("] ");
    return out;
}

std::wstring SessionPrefixW(const tConnectSettings* cs)
{
    if (!cs) return {};
    const std::string& name = !cs->DisplayName.empty() ? cs->DisplayName : cs->server;
    if (name.empty()) return {};
    // Session names are typically ASCII but may carry UTF-8 if a user picked
    // a non-Latin name. MultiByteToWideChar with CP_UTF8 covers both.
    const int wlen = MultiByteToWideChar(CP_UTF8, 0, name.c_str(),
                                         static_cast<int>(name.size()), nullptr, 0);
    if (wlen <= 0) return {};
    std::wstring w;
    w.resize(static_cast<size_t>(wlen) + 3);
    w[0] = L'[';
    MultiByteToWideChar(CP_UTF8, 0, name.c_str(), static_cast<int>(name.size()),
                        &w[1], wlen);
    w[1 + wlen] = L']';
    w[2 + wlen] = L' ';
    w.resize(static_cast<size_t>(wlen) + 3);
    return w;
}
} // namespace

SessionContextGuard::SessionContextGuard(const tConnectSettings* cs) noexcept
    : prev_(g_currentSession)
{
    g_currentSession = cs;
}

SessionContextGuard::~SessionContextGuard() noexcept
{
    g_currentSession = prev_;
}

const tConnectSettings* GetCurrentSession() noexcept
{
    return g_currentSession;
}

void ShowStatus(LPCSTR status) noexcept
{
    if (!LogProc) return;
    const std::string prefix = SessionPrefixA(g_currentSession);
    if (prefix.empty()) {
        LogProc(PluginNumber, MSGTYPE_DETAILS, status);
    } else {
        std::string full;
        full.reserve(prefix.size() + (status ? strlen(status) : 0));
        full.append(prefix);
        if (status) full.append(status);
        LogProc(PluginNumber, MSGTYPE_DETAILS, full.c_str());
    }
}

void ShowStatusW(LPCWSTR status) noexcept
{
    const std::wstring prefix = SessionPrefixW(g_currentSession);
    if (prefix.empty()) {
        LogProcT(PluginNumber, MSGTYPE_DETAILS, status);
    } else {
        std::wstring full;
        full.reserve(prefix.size() + (status ? wcslen(status) : 0));
        full.append(prefix);
        if (status) full.append(status);
        LogProcT(PluginNumber, MSGTYPE_DETAILS, full.c_str());
    }
}

// Returns true when operation should be aborted by user/progress callback.
bool UpdatePercentBar(pConnectSettings ConnectSettings, int percent, LPCWSTR source, LPCWSTR target) noexcept
{
    if (ConnectSettings) {
        ConnectSettings->lastpercent = percent;  // used for MessageLoop below
        if (source)
            wcslcpy(ConnectSettings->current_sourceW, source, countof(ConnectSettings->current_sourceW) - 1);

        if (target)
            wcslcpy(ConnectSettings->current_targetW, target, countof(ConnectSettings->current_targetW) - 1);
    }

    return MessageLoop(ConnectSettings);  // Updates the percent bar.
}

pConnectSettings GetServerIdAndRelativePathFromPath(LPCSTR Path, LPSTR RelativePath, size_t maxlen)
{
    if (!Path || !RelativePath || maxlen == 0)
        return nullptr;

    // Folder-aware resolver: identifies the session boundary by longest-prefix
    // match against the loaded registry, returning the remote sub-path
    // (already in backslash form) after the session prefix.
    const PathResolution r = ResolvePathKind(Path);
    pConnectSettings serverid = nullptr;
    if (r.kind == PathKind::SessionLeaf || r.kind == PathKind::SessionWithSubpath) {
        serverid = static_cast<pConnectSettings>(
            GetServerIdFromName(r.displayName.c_str(), GetCurrentThreadId()));
    }
    if (serverid && !r.relative.empty()) {
        strlcpy(RelativePath, r.relative.c_str(), maxlen - 1);
    } else {
        strlcpy(RelativePath, "\\", maxlen - 1);
    }
    return serverid;
}

pConnectSettings GetServerIdAndRelativePathFromPathW(LPCWSTR Path, LPWSTR RelativePath, size_t maxlen)
{
    if (!Path || !RelativePath || maxlen == 0)
        return nullptr;

    const PathResolution r = ResolvePathKindW(Path);
    pConnectSettings serverid = nullptr;
    if (r.kind == PathKind::SessionLeaf || r.kind == PathKind::SessionWithSubpath) {
        serverid = static_cast<pConnectSettings>(
            GetServerIdFromName(r.displayName.c_str(), GetCurrentThreadId()));
    }
    if (serverid && !r.relative.empty()) {
        std::array<wchar_t, wdirtypemax> wrel{};
        MultiByteToWideChar(CP_ACP, 0, r.relative.c_str(), -1,
                            wrel.data(), static_cast<int>(wrel.size()));
        wcslcpy(RelativePath, wrel.data(), maxlen - 1);
    } else {
        wcslcpy(RelativePath, L"\\", maxlen - 1);
    }
    return serverid;
}

__forceinline
void ResetLastPercent(pConnectSettings ConnectSettings)
{
    if (ConnectSettings)
        ConnectSettings->lastpercent = 0;
}

// Detects and applies TC language if not already loaded.
// Called from both FsSetDefaultParams and _FsInit to cover all load orders.
static void DetectAndApplyLanguage(const char* fallbackIniPath) noexcept
{
    if (g_wincmdIniPath[0])
        return;  // Already loaded by a prior call.

    std::array<char, MAX_PATH> tcIniPath{};

    HKEY hKey = nullptr;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Ghisler\\Total Commander",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD type = 0;
        DWORD bytes = static_cast<DWORD>(tcIniPath.size()) - 1;
        if (RegQueryValueExA(hKey, "IniFileName", nullptr, &type,
                             reinterpret_cast<LPBYTE>(tcIniPath.data()), &bytes) == ERROR_SUCCESS
            && (type == REG_SZ || type == REG_EXPAND_SZ)) {
            // Path retrieved from registry (may contain %APPDATA% etc.)
        } else {
            tcIniPath[0] = '\0';
        }
        RegCloseKey(hKey);
    }

    if (!tcIniPath[0] && fallbackIniPath && fallbackIniPath[0]) {
        strlcpy(tcIniPath.data(), fallbackIniPath, tcIniPath.size() - 1);
        char* slash = strrchr(tcIniPath.data(), '\\');
        if (slash) {
            slash[1] = '\0';
            strlcat(tcIniPath.data(), "wincmd.ini", tcIniPath.size() - 1);
        }
    }

    if (tcIniPath[0]) {
        strlcpy(g_wincmdIniPath, tcIniPath.data(), MAX_PATH - 1);
        ApplyTcLanguageToPluginResources(g_wincmdIniPath);
    }
}

static int _FsInit(int PluginNr)
{
    if (!g_winsockInitialized) {
        WSADATA wsaData{};
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            return 1;
        }
        g_winsockInitialized = true;
    }
    PluginNumber = PluginNr;
    mainthreadid = GetCurrentThreadId();

    // Emitted once per plugin load so a user submitting a bug report can
    // paste the log tail and everyone knows exactly which build they are
    // running — matters most in the beta cycle where version.h stays put
    // between beta1/2/... and only git tag + SHA differ.
    SFTP_LOG("STARTUP", "SFTPplug build tag=%s sha=%s date=%s",
             SFTP_BUILD_TAG, SFTP_BUILD_SHA, SFTP_BUILD_DATE);

    // Load language now in case FsSetDefaultParams was not called yet or registry lookup failed.
    DetectAndApplyLanguage(nullptr);

    InitMultiServer();
    StartGlobalLanServices();  // Start LAN Pair file server + discovery in background
    return 0;
}

int WINAPI FsInit(int PluginNr, tProgressProc pProgressProc, tLogProc pLogProc, tRequestProc pRequestProc)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, 1, [&]() -> int {
        ProgressProc = pProgressProc;
        LogProc = pLogProc;
        RequestProc = pRequestProc;
        return _FsInit(PluginNr);
    });
}

int WINAPI FsInitW(int PluginNr, tProgressProcW pProgressProcW, tLogProcW pLogProcW, tRequestProcW pRequestProcW)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, 1, [&]() -> int {
        ProgressProcW = pProgressProcW;
        LogProcW = pLogProcW;
        RequestProcW = pRequestProcW;
        return _FsInit(PluginNr);
    });
}

void WINAPI FsSetCryptCallback(tCryptProc pCryptProc, int CryptoNr, int Flags)
{
    sftp::DllExceptionBarrier _barrier;
    sftp::dll_invoke_void(_barrier, [&] {
        CryptProc = pCryptProc;
        CryptCheckPass = (Flags & FS_CRYPTOPT_MASTERPASS_SET) != 0;
        CryptoNumber = CryptoNr;
    });
}

BOOL WINAPI FsDisconnect(LPCSTR DisconnectRoot)
{
    sftp::DllExceptionBarrier _barrier;
    SFTP_LOG("DISCONNECT", "FsDisconnect ENTRY path='%s' tid=%lu",
             DisconnectRoot ? DisconnectRoot : "(null)",
             GetCurrentThreadId());
    return sftp::dll_invoke(_barrier, FALSE, [&]() -> BOOL {
        std::string displayName;
        displayName.resize(wdirtypemax);
        GetDisplayNameFromPath(DisconnectRoot, displayName.data(), displayName.size() - 1);
        displayName.resize(strlen(displayName.data()));
        SFTP_LOG("DISCONNECT", "  displayName='%s'", displayName.c_str());

        if (displayName.empty()) {
            SFTP_LOG("DISCONNECT", "  empty displayName, returning TRUE");
            return true;
        }

        // Thread-agnostic close: TC can post FsDisconnect from a
        // background thread (observed empirically when the click fires
        // while the panel is at plugin root `\`). The old code path
        // called GetServerIdFromName with GetCurrentThreadId(), and for
        // a background thread FindEntry with is_background=true+matching
        // tid returned null even though the main-thread entry existed —
        // the session leaked, its SSH channel stayed open, and the next
        // Enter reused the stale connection (visible to the user as
        // "instant reconnect without a key exchange").
        //
        // DisconnectServerByName closes the underlying SSH session once
        // and drops every registry row referencing this name regardless
        // of thread. Safe to call for background-thread invocations;
        // idempotent for a double-close (removed==0).
        std::string connBuf = "DISCONNECT \\";
        connBuf += displayName;
        LogProc(PluginNumber, MSGTYPE_DISCONNECT, connBuf.c_str());

        const size_t removed = DisconnectServerByName(displayName.c_str());
        SFTP_LOG("DISCONNECT", "  DisconnectServerByName removed=%zu", removed);

        // Housekeeping for virtual (Imports-backed) sessions — drop the
        // alias→(sourceId, cacheSection, displayName) binding so the map
        // does not grow unbounded across many connect/disconnect cycles.
        // No-op for native sessions and for double-disconnects.
        if (sftp::IsVirtualSessionAlias(displayName.data()))
            sftp::UnregisterVirtualSession(displayName);
        return true;
    });
}
// Status callbacks are handled through ANSI entry in current plugin ABI.
void WINAPI FsStatusInfo(LPCSTR RemoteDir, int InfoStartEnd, int InfoOperation)
{
    sftp::DllExceptionBarrier _barrier;
    sftp::dll_invoke_void(_barrier, [&] {
        SFTP_LOG("STATUS", "FsStatusInfo op=%d %s dir='%s'",
                 InfoOperation,
                 InfoStartEnd == FS_STATUS_START ? "START" : "END",
                 RemoteDir ? RemoteDir : "");

        if (strlen(RemoteDir) < 2)
            if (InfoOperation == FS_STATUS_OP_DELETE || InfoOperation == FS_STATUS_OP_RENMOV_MULTI)
                disablereading = (InfoStartEnd == FS_STATUS_START) ? true : false;

        // Track an in-progress bulk copy/move so FsMkDir/FsFindFirst suppress
        // the new-session dialog when TC is auto-creating destination folders
        // or probing a target path mid-transfer. RENMOV_MULTI applies to any
        // plugin path — TC's bulk rename/move probe is always an internal
        // check, never a user quick-connect. PUT_SINGLE / PUT_MULTI are gated
        // to destinations inside \[Imports]\ (a silent no-op region for
        // uploads); outside Imports a PUT to a valid-but-unconnected session
        // must auto-connect normally.
        const bool isPutOp = InfoOperation == FS_STATUS_OP_PUT_SINGLE ||
                             InfoOperation == FS_STATUS_OP_PUT_MULTI;
        const bool destInImports = RemoteDir &&
            _strnicmp(RemoteDir, "\\[Imports]\\", 11) == 0;
        if (InfoOperation == FS_STATUS_OP_RENMOV_MULTI ||
            (isPutOp && destInImports))
        {
            g_inMultiOpTransfer = (InfoStartEnd == FS_STATUS_START);
        }

        if (InfoOperation == FS_STATUS_OP_PUT_MULTI ||
            InfoOperation == FS_STATUS_OP_PUT_SINGLE) {
            std::array<char, wdirtypemax> remotedir{};
            pConnectSettings cs = GetServerIdAndRelativePathFromPath(RemoteDir, remotedir.data(), remotedir.size() - 1);
            if (InfoStartEnd == FS_STATUS_START) {
                SFTP_LOG("STATUS", "PUT START: php_tar=%d isPhpAgent=%d tarActive=%d",
                         cs ? cs->php_tar : -1,
                         cs ? IsPhpAgentTransport(cs) : -1,
                         TarUploadSessionIsActive() ? 1 : 0);
                if (cs && IsPhpAgentTransport(cs) && cs->php_tar)
                    TarUploadSessionBegin(cs);
            } else {
                SFTP_LOG("STATUS", "PUT END: tarActive=%d", TarUploadSessionIsActive() ? 1 : 0);
                if (TarUploadSessionIsActive()) {
                    const int rc = TarUploadSessionExecuteAndClear();
                    SFTP_LOG("STATUS", "PUT END: TarExecute rc=%d", rc);
                    if (rc != SFTP_OK && rc != SFTP_ABORT)
                        ShowStatusId(IDS_LOG_TAR_UPLOAD_FAIL, nullptr, false);
                }
            }
        }

        if (InfoOperation == FS_STATUS_OP_GET_MULTI ||
            InfoOperation == FS_STATUS_OP_GET_SINGLE) {
            std::array<char, wdirtypemax> remotedir{};
            pConnectSettings cs = GetServerIdAndRelativePathFromPath(RemoteDir, remotedir.data(), remotedir.size() - 1);
            if (InfoStartEnd == FS_STATUS_START) {
                SFTP_LOG("STATUS", "GET START: php_tar=%d isPhpAgent=%d tarDlActive=%d",
                         cs ? cs->php_tar : -1,
                         cs ? IsPhpAgentTransport(cs) : -1,
                         TarDownloadSessionIsActive() ? 1 : 0);
                if (cs && IsPhpAgentTransport(cs) && cs->php_tar)
                    TarDownloadSessionBegin(cs);
            } else {
                SFTP_LOG("STATUS", "GET END: tarDlActive=%d", TarDownloadSessionIsActive() ? 1 : 0);
                if (TarDownloadSessionIsActive()) {
                    const int rc = TarDownloadSessionExecuteAndClear();
                    SFTP_LOG("STATUS", "GET END: TarDlExecute rc=%d", rc);
                    if (rc != SFTP_OK && rc != SFTP_ABORT)
                        ShowStatusId(IDS_LOG_TAR_UPLOAD_FAIL, nullptr, false);
                }
            }
        }

        if (InfoOperation == FS_STATUS_OP_GET_MULTI_THREAD || InfoOperation == FS_STATUS_OP_PUT_MULTI_THREAD) {
            if (InfoStartEnd != FS_STATUS_START) {
                if (InfoOperation == FS_STATUS_OP_PUT_MULTI_THREAD && TarUploadSessionIsActive()) {
                    const int rc = TarUploadSessionExecuteAndClear();
                    if (rc != SFTP_OK && rc != SFTP_ABORT)
                        ShowStatusId(IDS_LOG_TAR_UPLOAD_FAIL, nullptr, false);
                }
                if (InfoOperation == FS_STATUS_OP_GET_MULTI_THREAD && TarDownloadSessionIsActive()) {
                    const int rc = TarDownloadSessionExecuteAndClear();
                    if (rc != SFTP_OK && rc != SFTP_ABORT)
                        ShowStatusId(IDS_LOG_TAR_UPLOAD_FAIL, nullptr, false);
                }
                FsDisconnect(RemoteDir);
                return;
            }
            std::array<char, MAX_PATH> displayName{};
            const char* oldpass = nullptr;
            GetDisplayNameFromPath(RemoteDir, displayName.data(), displayName.size() - 1);
            // get password from main thread
            pConnectSettings oldserverid = static_cast<pConnectSettings>(GetServerIdFromName(displayName.data(), mainthreadid));
            if (oldserverid) {
                if (InfoOperation == FS_STATUS_OP_PUT_MULTI_THREAD
                    && IsPhpAgentTransport(oldserverid) && oldserverid->php_tar)
                    TarUploadSessionBegin(nullptr);  // cs filled in by first FsPutFileW
                if (InfoOperation == FS_STATUS_OP_GET_MULTI_THREAD
                    && IsPhpAgentTransport(oldserverid) && oldserverid->php_tar)
                    TarDownloadSessionBegin(nullptr);  // cs filled in by first FsGetFileW
                oldpass = oldserverid->password.c_str();
                if (!oldpass[0])
                    oldpass = nullptr;
            }
            pConnectSettings serverid = SftpConnectToServer(displayName.data(), inifilename, oldpass);
            if (serverid)
                SetServerIdForName(displayName.data(), static_cast<SERVERID>(serverid));
        }
    });
}

void WINAPI FsGetDefRootName(LPSTR DefRootName, int maxlen)
{
    sftp::DllExceptionBarrier _barrier;
    sftp::dll_invoke_void(_barrier, [&] {
        if (!DefRootName || maxlen <= 0)
            return;
        strlcpy(DefRootName, defrootname, maxlen);
    });
}

// Use the default location but keep the plugin-specific INI file name.
void WINAPI FsSetDefaultParams(FsDefaultParamStruct * dps)
{
    sftp::DllExceptionBarrier _barrier;
    sftp::dll_invoke_void(_barrier, [&] {
        if (dps) {
            // Detect wincmd.ini from registry, falling back to the path derived from dps->DefaultIniName.
            DetectAndApplyLanguage(dps->DefaultIniName);
        }

        strlcpy(inifilename, dps->DefaultIniName, MAX_PATH-1);
        LPSTR p = strrchr(inifilename, '\\');
        if (p)
            p[1] = 0;
        else
            inifilename[0] = 0;
        strlcat(inifilename, defininame, countof(inifilename)-1);

        // Build the Unicode version of the ini path so that ini access works
        // correctly even when the user profile directory contains non-ANSI characters.
        MultiByteToWideChar(CP_ACP, 0, inifilename, -1, inifilenameW, MAX_PATH);

        // Apply language override from sftpplug.ini [Configuration] Language= (overrides TC detection).
        {
            std::array<wchar_t, 64> langOverride{};
            GetPrivateProfileStringW(L"Configuration", L"Language", L"",
                                     langOverride.data(), static_cast<DWORD>(langOverride.size()),
                                     inifilenameW);
            if (langOverride[0]) {
                const LANGID overrideId = LangNameToId(langOverride.data());
                if (overrideId != 0) {
                    ApplyLangId(overrideId);
                } else {
                    // Unknown name — treat as a custom .lng filename stem.
                    // E.g. Language=fin  loads  language\fin.lng  without a LANGID mapping.
                    std::string code;
                    for (const wchar_t* p = langOverride.data(); *p; ++p)
                        code += static_cast<char>(towlower(*p));
                    LngLoadByCode(code.c_str(), hinst);
                }
            }
        }

        // Copy INI template from plugin directory if present.
        std::array<char, MAX_PATH> templateName{};
        DWORD len = GetModuleFileName(hinst, templateName.data(), templateName.size() - 1);
        if (len > 0) {
            LPSTR p = strrchr(templateName.data(), '\\');
            if (p) {
                p[1] = 0;
                strlcat(templateName.data(), templatefile, templateName.size() - 1);
            }
            CopyFileA(templateName.data(), inifilename, true);  // only copy if target doesn't exist
        }
    });
}

// Icon selection for entries under `\[Imports]\`. Returns FS_ICON_USEDEFAULT
// (fall through to the caller's default logic) when the path is not an
// Imports leaf, or when no Imports rule matched — the caller then handles
// regular saved-session rendering. Returns FS_ICON_EXTRACTED or
// FS_ICON_EXTRACTED_DESTROY when a specific icon was selected.
static int TryExtractImportIcon(LPCSTR RemoteName, int ExtractFlags, HICON* TheIcon)
{
    const std::wstring w = unicode_util::narrow_to_wide(RemoteName);
    if (w.empty()) return FS_ICON_USEDEFAULT;

    std::string sourceId, subPath;
    if (ClassifyImportsPath(w.c_str(), &sourceId, &subPath) !=
        ImportsPathKind::SourceSubPath)
    {
        return FS_ICON_USEDEFAULT;
    }

    const bool sm = (ExtractFlags & FS_ICONFLAG_SMALL) != 0;

    // Gear icon (imageres.dll resource id 114 = Control Panel gear on
    // Windows 10/11) for the two action pseudo entries. ExtractIconExW
    // hands us fresh HICONs we own, hence FS_ICON_EXTRACTED_DESTROY. Note:
    // `small` is a legacy RPC macro from windows.h that expands to `char`,
    // so we use *Icon suffixes for the locals. The gear glyph carries a
    // checkbox-corner overlay baked into the shipped Windows icon; a
    // proper plugin-owned .ico set is the follow-up task recorded in TODO.
    if (subPath == kRefreshEntry || subPath == kAddCustomEntry) {
        HICON largeIcon = nullptr, smallIcon = nullptr;
        const UINT extracted = ExtractIconExW(L"imageres.dll",
            -114, &largeIcon, &smallIcon, 1);
        HICON pick = sm ? smallIcon : largeIcon;
        HICON drop = sm ? largeIcon : smallIcon;
        if (drop) DestroyIcon(drop);
        if (extracted > 0 && pick) {
            *TheIcon = pick;
            return FS_ICON_EXTRACTED_DESTROY;
        }
        return FS_ICON_USEDEFAULT;
    }

    // "not currently detected" hint keeps the classic Windows warning
    // triangle via LoadIcon (shared handle, so plain FS_ICON_EXTRACTED).
    if (subPath.find("not currently detected") != std::string::npos) {
        HICON h = LoadIconW(nullptr, MAKEINTRESOURCEW(32515));  // IDI_WARNING
        if (h) {
            *TheIcon = h;
            return FS_ICON_EXTRACTED;
        }
        return FS_ICON_USEDEFAULT;
    }

    // Virtual session leaves inside a source (e.g. [Imports]\[SecureCRT]\
    // dron\hz-1) get the same padlock glyph as real saved sessions so the
    // user reads them as sessions. The distinguisher against nested folder
    // segments (dron, my, ...) is a direct match against
    // ImportCache::ListSource — only leaf sessions have an entry there.
    // Skip when subPath is under the [Manage custom locations] sub-tree.
    const std::string managePrefix = std::string(kManageCustomFolder) + "/";
    if (subPath == kManageCustomFolder ||
        subPath.compare(0, managePrefix.size(), managePrefix) == 0)
    {
        return FS_ICON_USEDEFAULT;
    }
    const auto sessions = sftp::GetImportCache().ListSource(sourceId);
    for (const auto& s : sessions) {
        if (_stricmp(s.displayName.c_str(), subPath.c_str()) == 0) {
            LPCSTR name = MAKEINTRESOURCEA(sm ? IDI_ICON1SMALL : IDI_ICON1);
            *TheIcon = LoadIconA(hinst, name);
            return FS_ICON_EXTRACTED;
        }
    }
    return FS_ICON_USEDEFAULT;
}

int WINAPI FsExtractCustomIcon(LPCSTR RemoteName, int ExtractFlags, HICON * TheIcon)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, FS_ICON_USEDEFAULT, [&]() -> int {
        if (!RemoteName || strlen(RemoteName) <= 1)
            return FS_ICON_USEDEFAULT;

        // Import-magic-folder pseudo entries and virtual session rows use
        // their own icon set (Windows stock glyphs + our padlock). The
        // WFX icon API is ANSI-only, so the widening happens inside the
        // helper.
        const int importResult = TryExtractImportIcon(RemoteName, ExtractFlags, TheIcon);
        if (importResult != FS_ICON_USEDEFAULT)
            return importResult;

        // Supply our padlock icon for any leaf session entry, whether it's
        // at the plugin root or nested inside a folder. Anything else
        // (folder grouping, file inside an active session) keeps TC's
        // default rendering.
        const PathResolution r = ResolvePathKind(RemoteName);
        if (r.kind != PathKind::SessionLeaf)
            return FS_ICON_USEDEFAULT;
        if (_stricmp(r.displayName.c_str(), s_f7newconnection) == 0)
            return FS_ICON_USEDEFAULT;  // pseudo helper — let TC pick a default
        const bool sm = (ExtractFlags & FS_ICONFLAG_SMALL) != 0;
        pConnectSettings serverid = static_cast<pConnectSettings>(
            GetServerIdFromName(r.displayName.c_str(), GetCurrentThreadId()));
        // Connected sessions get a distinguishing icon variant.
        LPCSTR lpIconName = serverid
            ? MAKEINTRESOURCEA(sm ? IDI_ICON2SMALL : IDI_ICON2)
            : MAKEINTRESOURCEA(sm ? IDI_ICON1SMALL : IDI_ICON1);
        *TheIcon = LoadIconA(hinst, lpIconName);
        return FS_ICON_EXTRACTED;
    });
}

int WINAPI FsGetBackgroundFlags(void)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, 0, [&]() -> int {
        return BG_DOWNLOAD | BG_UPLOAD | BG_ASK_USER;
    });
}

int WINAPI FsServerSupportsChecksumsW(LPCWSTR RemoteName)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, 0, [&]() -> int {
        std::array<WCHAR, wdirtypemax> remotedir{};
        pConnectSettings serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir.data(), remotedir.size() - 1);
        if (serverid == nullptr)
            return 0;
        ResetLastPercent(serverid);
        return SftpServerSupportsChecksumsW(serverid, remotedir.data());
    });
}

int WINAPI FsServerSupportsChecksums(LPCSTR RemoteName)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, 0, [&]() -> int {
        std::array<WCHAR, wdirtypemax> remoteNameW{};
        return FsServerSupportsChecksumsW(awlcopy(remoteNameW.data(), RemoteName, remoteNameW.size() - 1));
    });
}

HANDLE WINAPI FsStartFileChecksumW(int ChecksumType, LPCWSTR RemoteName)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, nullptr, [&]() -> HANDLE {
        std::array<WCHAR, wdirtypemax> remotedir{};
        pConnectSettings serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir.data(), remotedir.size() - 1);
        if (serverid == nullptr)
            return nullptr;
        ResetLastPercent(serverid);
        return SftpStartFileChecksumW(ChecksumType, serverid, remotedir.data());
    });
}

HANDLE WINAPI FsStartFileChecksum(int ChecksumType, LPCSTR RemoteName)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, nullptr, [&]() -> HANDLE {
        std::array<WCHAR, wdirtypemax> remoteNameW{};
        return FsStartFileChecksumW(ChecksumType, awlcopy(remoteNameW.data(), RemoteName, remoteNameW.size() - 1));
    });
}


int WINAPI FsGetFileChecksumResultW(BOOL WantResult, HANDLE ChecksumHandle, LPCWSTR RemoteName, LPSTR checksum, int maxlen)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, 0, [&]() -> int {
        std::array<WCHAR, wdirtypemax> remotedir{};
        pConnectSettings serverid = GetServerIdAndRelativePathFromPathW(RemoteName, remotedir.data(), remotedir.size() - 1);
        if (serverid == nullptr)
            return 0;
        ResetLastPercent(serverid);
        return SftpGetFileChecksumResultW(!!WantResult, ChecksumHandle, serverid, checksum, maxlen);
    });
}

int WINAPI FsGetFileChecksumResult(BOOL WantResult, HANDLE ChecksumHandle, LPCSTR RemoteName, LPSTR checksum, int maxlen)
{
    sftp::DllExceptionBarrier _barrier;
    return sftp::dll_invoke(_barrier, 0, [&]() -> int {
        std::array<WCHAR, wdirtypemax> remoteNameW{};
        return FsGetFileChecksumResultW(!!WantResult, ChecksumHandle, awlcopy(remoteNameW.data(), RemoteName, remoteNameW.size() - 1), checksum, maxlen);
    });
}
