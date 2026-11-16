// Drives a built SFTPplug.wfx through the exported Fs* entry points Total
// Commander uses, against a real SSH server, without Total Commander.
//
//   plugin_harness <plugin.wfx> <ini-dir> <session> <remote-base> <mode>
//
//   ini-dir      directory holding the sftpplug.ini the plugin is pointed at
//   session      section of that ini to connect with
//   remote-base  existing writable remote directory, e.g. /tmp
//   mode         the transfer mode the session is set up for (sftp, scp,
//                scponly, shell, text, text-scp, text-scponly, nosub,
//                nosub-bad, postcmd, key-*, classic-gate, secrets); the text* modes
//                also run the text-mode (CRLF <-> LF) checks; secrets needs no
//                server: it checks where passwords end up when sessions are
//                imported, exported, copied, renamed and deleted
//
// Environment: SFTP_IT_POSTCMD_EXPECT, the line the post-login command
// prints (mode postcmd); SFTP_IT_RESTART_CMD, a command that restarts the
// server mid-run, after which the session has to reconnect (mode nosub).
//
// Non-destructive by construction: everything the run creates lives in
// <remote-base>/sftpplug-it-<random>, and only that directory is removed.
// The plugin's prompts are answered by policy, never by a person: a host key
// is accepted only when SFTP_IT_ACCEPT_NEW_HOSTKEY=1, and any other unexpected
// prompt is declined and fails the run.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <fstream>
#include <iterator>
#include <map>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <vector>

// Total Commander's plugin header uses an anonymous union.
#include "fsplugin.h"

#pragma comment(lib, "bcrypt.lib")

namespace {

// ---------------------------------------------------------------------------
// Plugin exports
// ---------------------------------------------------------------------------
struct Plugin {
    HMODULE module = nullptr;
    int (WINAPI* InitW)(int, tProgressProcW, tLogProcW, tRequestProcW) = nullptr;
    void (WINAPI* SetDefaultParams)(FsDefaultParamStruct*) = nullptr;
    HANDLE (WINAPI* FindFirstW)(LPCWSTR, LPWIN32_FIND_DATAW) = nullptr;
    BOOL (WINAPI* FindNextW)(HANDLE, LPWIN32_FIND_DATAW) = nullptr;
    int (WINAPI* FindClose)(HANDLE) = nullptr;
    BOOL (WINAPI* MkDirW)(LPCWSTR) = nullptr;
    BOOL (WINAPI* RemoveDirW)(LPCWSTR) = nullptr;
    BOOL (WINAPI* DeleteFileW)(LPCWSTR) = nullptr;
    int (WINAPI* PutFileW)(LPCWSTR, LPCWSTR, int) = nullptr;
    int (WINAPI* GetFileW)(LPCWSTR, LPWSTR, int, RemoteInfoStruct*) = nullptr;
    int (WINAPI* RenMovFileW)(LPCWSTR, LPCWSTR, BOOL, BOOL, RemoteInfoStruct*) = nullptr;
    int (WINAPI* ExecuteFileW)(HWND, LPWSTR, LPCWSTR) = nullptr;
    BOOL (WINAPI* Disconnect)(LPCSTR) = nullptr;
    void (WINAPI* StatusInfoW)(LPCWSTR, int, int) = nullptr;
    void (WINAPI* SetCryptCallbackW)(tCryptProcW, int, int) = nullptr;

    template <class F> bool Bind(F& fn, const char* name)
    {
        fn = reinterpret_cast<F>(GetProcAddress(module, name));
        if (!fn)
            std::printf("FATAL export %s missing\n", name);
        return fn != nullptr;
    }

    bool Load(const wchar_t* path)
    {
        module = LoadLibraryW(path);
        if (!module) {
            std::printf("FATAL cannot load plugin (error %lu)\n", GetLastError());
            return false;
        }
        return Bind(InitW, "FsInitW") && Bind(SetDefaultParams, "FsSetDefaultParams") &&
               Bind(FindFirstW, "FsFindFirstW") && Bind(FindNextW, "FsFindNextW") && Bind(FindClose, "FsFindClose") &&
               Bind(MkDirW, "FsMkDirW") && Bind(RemoveDirW, "FsRemoveDirW") && Bind(DeleteFileW, "FsDeleteFileW") &&
               Bind(PutFileW, "FsPutFileW") && Bind(GetFileW, "FsGetFileW") && Bind(RenMovFileW, "FsRenMovFileW") &&
               Bind(ExecuteFileW, "FsExecuteFileW") && Bind(Disconnect, "FsDisconnect") &&
               Bind(StatusInfoW, "FsStatusInfoW") && Bind(SetCryptCallbackW, "FsSetCryptCallbackW");
    }
} g_plugin;

// ---------------------------------------------------------------------------
// Callbacks
// ---------------------------------------------------------------------------
int g_unexpectedPrompts = 0;
int g_messages = 0;
std::wstring g_lastMessage;
bool g_verbose = false;

std::string Narrow(const std::wstring& w)
{
    if (w.empty())
        return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    std::string s(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), s.data(), n, nullptr, nullptr);
    return s;
}

bool EnvIs(const wchar_t* name, const wchar_t* value)
{
    wchar_t buf[16] = {};
    return GetEnvironmentVariableW(name, buf, 16) > 0 && std::wcscmp(buf, value) == 0;
}

int WINAPI OnProgress(int, LPCWSTR, LPCWSTR, int) { return 0; }

// What the plugin writes to Total Commander's log window. Background
// transfers log from their own threads.
std::vector<std::wstring> g_logLines;
std::mutex g_logMutex;

void WINAPI OnLog(int, int, LPCWSTR text)
{
    if (text) {
        std::lock_guard<std::mutex> lock(g_logMutex);
        g_logLines.emplace_back(text);
    }
    if (g_verbose && text)
        std::printf("      log: %s\n", Narrow(text).c_str());
}

// How many times the plugin reported a new connection in TC's log.
int CountConnects()
{
    std::lock_guard<std::mutex> lock(g_logMutex);
    int n = 0;
    for (const auto& line : g_logLines)
        if (line.rfind(L"CONNECT ", 0) == 0)
            ++n;
    return n;
}

std::wstring EnvString(const wchar_t* name)
{
    wchar_t buf[1024] = {};
    const DWORD n = GetEnvironmentVariableW(name, buf, 1024);
    return n > 0 && n < 1024 ? std::wstring(buf, n) : std::wstring();
}

BOOL WINAPI OnRequest(int, int type, LPCWSTR title, LPCWSTR text, LPWSTR returned, int maxlen)
{
    const std::wstring t = text ? text : L"";
    const std::wstring all = (title ? std::wstring(title) + L" | " : std::wstring()) + t;
    // The message follows Total Commander's language, the title does not.
    const bool aboutHostKey = (title && std::wcscmp(title, L"SFTP Security Warning") == 0) ||
                              t.find(L"ingerprint") != std::wstring::npos;
    if ((type == RT_MsgYesNo || type == RT_MsgOKCancel) && aboutHostKey) {
        const bool accept = EnvIs(L"SFTP_IT_ACCEPT_NEW_HOSTKEY", L"1");
        std::printf("      prompt (host key, %s): %s\n", accept ? "accepted" : "declined", Narrow(all).c_str());
        if (!accept)
            ++g_unexpectedPrompts;
        return accept;
    }
    // A key passphrase, when the run supplies one: typed the same way for
    // every key, the plugin works out the bytes the key was protected with.
    wchar_t passphrase[128] = {};
    if (type == RT_Password && returned && maxlen > 0 &&
        GetEnvironmentVariableW(L"SFTP_IT_PASSPHRASE", passphrase, 128) > 0) {
        wcsncpy_s(returned, static_cast<size_t>(maxlen), passphrase, _TRUNCATE);
        std::printf("      prompt (passphrase, answered): %s\n", Narrow(all).c_str());
        return TRUE;
    }
    if (type == RT_MsgOK) {
        ++g_messages;
        g_lastMessage = all;
        std::printf("      message: %s\n", Narrow(all).c_str());
        return TRUE;
    }
    std::printf("      UNEXPECTED prompt type %d declined: %s\n", type, Narrow(all).c_str());
    ++g_unexpectedPrompts;
    return FALSE;
}

// Total Commander's password manager, kept in memory: the master password
// counts as entered, so nothing is ever asked.
std::map<std::wstring, std::wstring> g_store;

int WINAPI OnCrypt(int, int, int mode, LPCWSTR name, LPWSTR password, int maxlen)
{
    const std::wstring key = name ? name : L"";
    switch (mode) {
    case FS_CRYPT_SAVE_PASSWORD:
        g_store[key] = password ? password : L"";
        return FS_FILE_OK;
    case FS_CRYPT_LOAD_PASSWORD:
    case FS_CRYPT_LOAD_PASSWORD_NO_UI: {
        const auto it = g_store.find(key);
        if (it == g_store.end())
            return FS_FILE_READERROR;
        wcsncpy_s(password, static_cast<size_t>(maxlen), it->second.c_str(), _TRUNCATE);
        return FS_FILE_OK;
    }
    case FS_CRYPT_COPY_PASSWORD:
    case FS_CRYPT_MOVE_PASSWORD: {
        const auto it = g_store.find(key);
        if (it == g_store.end())
            return FS_FILE_READERROR;
        const std::wstring value = it->second;
        if (mode == FS_CRYPT_MOVE_PASSWORD)
            g_store.erase(it);
        g_store[password] = value;
        return FS_FILE_OK;
    }
    case FS_CRYPT_DELETE_PASSWORD:
        g_store.erase(key);
        return FS_FILE_OK;
    }
    return FS_FILE_NOTSUPPORTED;
}

std::wstring StoreValue(const std::wstring& key)
{
    const auto it = g_store.find(key);
    return it == g_store.end() ? L"(none)" : it->second;
}

// ---------------------------------------------------------------------------
// Checks and helpers
// ---------------------------------------------------------------------------
int g_passed = 0;
int g_failed = 0;

bool Check(bool ok, const std::string& what)
{
    std::printf("  %s %s\n", ok ? "ok  " : "FAIL", what.c_str());
    (ok ? g_passed : g_failed)++;
    return ok;
}

// A failure already listed as open work: shown, but not counted against
// the run, and reported as passing once it is fixed.
int g_known = 0;

void Known(bool ok, const std::string& what)
{
    std::printf("  %s %s\n", ok ? "ok  " : "KNOWN", what.c_str());
    (ok ? g_passed : g_known)++;
}

bool LocalExists(const std::wstring& path)
{
    return GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES;
}

std::string Sha256File(const std::wstring& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in)
        return "unreadable";
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0);
    std::vector<char> buf(1 << 16);
    while (in) {
        in.read(buf.data(), static_cast<std::streamsize>(buf.size()));
        if (in.gcount() > 0)
            BCryptHashData(hash, reinterpret_cast<PUCHAR>(buf.data()), static_cast<ULONG>(in.gcount()), 0);
    }
    UCHAR digest[32] = {};
    BCryptFinishHash(hash, digest, sizeof(digest), 0);
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    std::string hex;
    for (UCHAR b : digest) {
        char two[3];
        std::snprintf(two, sizeof(two), "%02x", b);
        hex += two;
    }
    return hex;
}

void WriteFileBytes(const std::wstring& path, const std::string& bytes)
{
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
}

std::string RandomBytes(size_t n, uint32_t seed)
{
    std::mt19937 rng(seed);
    std::string s(n, '\0');
    for (auto& c : s)
        c = static_cast<char>(rng() & 0xFF);
    return s;
}

struct RemoteEntry {
    uint64_t size = 0;
    DWORD attributes = 0;
    DWORD unixMode = 0;
};

std::map<std::wstring, RemoteEntry> ListDir(const std::wstring& tcPath, bool& ok)
{
    std::map<std::wstring, RemoteEntry> entries;
    WIN32_FIND_DATAW fd{};
    HANDLE h = g_plugin.FindFirstW(tcPath.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) {
        ok = GetLastError() == ERROR_NO_MORE_FILES;
        return entries;
    }
    ok = true;
    do {
        const std::wstring name = fd.cFileName;
        if (name == L"." || name == L"..")
            continue;
        RemoteEntry e;
        e.size = (static_cast<uint64_t>(fd.nFileSizeHigh) << 32) | fd.nFileSizeLow;
        e.attributes = fd.dwFileAttributes;
        e.unixMode = (fd.dwFileAttributes & FS_ATTR_UNIXMODE) ? fd.dwReserved0 : 0;
        entries[name] = e;
    } while (g_plugin.FindNextW(h, &fd));
    g_plugin.FindClose(h);
    return entries;
}

// Total Commander always passes what its listing knows about the source of a
// download; the plugin relies on the size it gets here.
RemoteInfoStruct InfoFor(const std::wstring& dir, const std::wstring& name)
{
    RemoteInfoStruct ri{};
    bool ok = false;
    const auto entries = ListDir(dir, ok);
    const auto it = entries.find(name);
    if (it != entries.end()) {
        ri.SizeLow = static_cast<DWORD>(it->second.size & 0xFFFFFFFFu);
        ri.SizeHigh = static_cast<DWORD>(it->second.size >> 32);
        ri.Attr = it->second.attributes;
    }
    return ri;
}

std::wstring NewTempDir(const wchar_t* tag)
{
    wchar_t base[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, base);
    std::wstring dir = std::wstring(base) + L"sftpplug-it-" + tag + L"-" + std::to_wstring(GetCurrentProcessId());
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir + L"\\";
}

} // namespace

int wmain(int argc, wchar_t** argv)
{
    SetConsoleOutputCP(CP_UTF8);
    if (argc < 6) {
        std::printf("usage: plugin_harness <plugin.wfx> <ini-dir> <session> <remote-base> <mode>\n");
        return 2;
    }
    const std::wstring pluginPath = argv[1];
    const std::wstring iniDir = argv[2];
    const std::wstring session = argv[3];
    std::wstring remoteBase = argv[4];
    const std::wstring mode = argv[5];
    const bool textChecks = mode.rfind(L"text", 0) == 0;
    const bool shellMode = mode == L"scponly" || mode == L"shell" || mode == L"text-scponly";
    g_verbose = EnvIs(L"SFTP_IT_VERBOSE", L"1");

    for (auto& c : remoteBase)
        if (c == L'/') c = L'\\';
    if (!remoteBase.empty() && remoteBase.back() == L'\\')
        remoteBase.pop_back();

    if (!g_plugin.Load(pluginPath.c_str()))
        return 2;
    g_plugin.InitW(1, OnProgress, OnLog, OnRequest);
    FsDefaultParamStruct dps{};
    dps.size = sizeof(dps);
    dps.PluginInterfaceVersionLow = 30;
    dps.PluginInterfaceVersionHi = 2;
    WideCharToMultiByte(CP_ACP, 0, (iniDir + L"\\fsplugin.ini").c_str(), -1, dps.DefaultIniName, MAX_PATH, nullptr, nullptr);
    g_plugin.SetDefaultParams(&dps);

    // A random suffix keeps parallel or repeated runs apart.
    std::random_device rd;
    const std::wstring runName = L"sftpplug-it-" + std::to_wstring(rd() % 1000000000u);
    const std::wstring root = L"\\" + session + remoteBase;
    const std::wstring dir = root + L"\\" + runName;
    std::printf("session %s, remote directory %s\n", Narrow(session).c_str(), Narrow(dir).c_str());

    if (mode == L"nosub-bad") {
        // A server without the sftp subsystem and a server command that
        // does not exist: the connection fails, and soon.
        const ULONGLONG start = GetTickCount64();
        bool listedBad = true;
        ListDir(root, listedBad);
        const ULONGLONG seconds = (GetTickCount64() - start) / 1000;
        Check(!listedBad, "a wrong SFTP server command fails to connect");
        Check(seconds < 30, "and gives up in " + std::to_string(seconds) + " s, no hang");
        std::printf("%d passed, %d failed, %d known\n", g_passed, g_failed, g_known);
        return g_failed == 0 ? 0 : 1;
    }

    if (mode == L"classic-gate") {
        // A PHP Agent session pointed at the SSH bench, with a key that
        // works there: the classic build refuses it, and must not connect
        // over SSH instead.
        bool listedGate = true;
        ListDir(root, listedGate);
        Check(!listedGate, "a PHP Agent session is not connected by the classic build");
        Check(g_lastMessage.find(L"extra build") != std::wstring::npos,
              "the refusal names the extra build");
        std::printf("%d passed, %d failed, %d known\n", g_passed, g_failed, g_known);
        return g_failed == 0 ? 0 : 1;
    }

    if (mode == L"secrets") {
        g_plugin.SetCryptCallbackW(OnCrypt, 1, FS_CRYPTOPT_MASTERPASS_SET);
        const std::wstring iniPath = iniDir + L"\\sftpplug.ini";
        const auto iniValue = [&](const wchar_t* section, const wchar_t* key) {
            wchar_t buf[512] = {};
            GetPrivateProfileStringW(section, key, L"(none)", buf, 512, iniPath.c_str());
            return std::wstring(buf);
        };
        const std::wstring local = NewTempDir(L"secrets");
        RemoteInfoStruct ri{};

        // A session file with passwords, copied into the plugin: they land
        // in the password manager, the INI holding "!".
        WriteFileBytes(local + L"in.ini", "[x]\r\nserver=127.0.0.1:1\r\nuser=u\r\n"
                                          "password=plain:secret1\r\njumppassword=plain:jsecret\r\n");
        // TC copies in the background the way it does everything else:
        // START and END around it, for the plugin root. Nothing there to
        // connect to (with a connection dialog this run would hang).
        g_plugin.StatusInfoW(L"\\", FS_STATUS_START, FS_STATUS_OP_PUT_MULTI_THREAD);
        Check(g_plugin.PutFileW((local + L"in.ini").c_str(), L"\\it-imp.ini", 0) == FS_FILE_OK,
              "a session file is copied into the plugin");
        g_plugin.StatusInfoW(L"\\", FS_STATUS_END, FS_STATUS_OP_PUT_MULTI_THREAD);
        Check(iniValue(L"it-imp", L"password") == L"!" && iniValue(L"it-imp", L"jumppassword") == L"!",
              "its passwords are not in the INI, only \"!\"");
        Check(StoreValue(L"it-imp") == L"secret1" && StoreValue(L"it-imp$$jump") == L"jsecret",
              "its passwords are in the password manager");

        // "!" in a foreign file must not bind to this machine's entry of the
        // same name.
        g_store[L"it-victim"] = L"realpw";
        WriteFileBytes(local + L"evil.ini", "[x]\r\nserver=127.0.0.1:2\r\npassword=!\r\njumppassword=!\r\n");
        Check(g_plugin.PutFileW((local + L"evil.ini").c_str(), L"\\it-victim.ini", FS_COPYFLAGS_OVERWRITE) == FS_FILE_OK,
              "a session file with \"!\" is copied into the plugin");
        Check(iniValue(L"it-victim", L"password") == L"(none)" &&
              iniValue(L"it-victim", L"jumppassword") == L"(none)",
              "\"!\" from a file brings no password");

        // Out to a file: the passwords readable, loaded from the manager.
        const std::wstring out = local + L"out.ini";
        Check(g_plugin.GetFileW(L"\\it-imp", const_cast<LPWSTR>(out.c_str()), FS_COPYFLAGS_OVERWRITE, &ri) == FS_FILE_OK,
              "a session is copied out to a file");
        std::string exported;
        {
            std::ifstream in(out, std::ios::binary);
            exported.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
        }
        Check(exported.find("password=plain:secret1") != std::string::npos &&
              exported.find("jumppassword=plain:jsecret") != std::string::npos,
              "the file has its passwords as plain:");

        // Rename and copy inside the plugin carry the manager's entries.
        Check(g_plugin.RenMovFileW(L"\\it-imp", L"\\it-imp2", TRUE, FALSE, &ri) == FS_FILE_OK,
              "a session is renamed");
        Check(StoreValue(L"it-imp2") == L"secret1" && StoreValue(L"it-imp2$$jump") == L"jsecret" &&
              StoreValue(L"it-imp") == L"(none)" && StoreValue(L"it-imp$$jump") == L"(none)",
              "its passwords move with it");
        Check(g_plugin.RenMovFileW(L"\\it-imp2", L"\\it-imp3", FALSE, FALSE, &ri) == FS_FILE_OK,
              "a session is copied");
        Check(StoreValue(L"it-imp3") == L"secret1" && StoreValue(L"it-imp3$$jump") == L"jsecret" &&
              StoreValue(L"it-imp2") == L"secret1",
              "the copy has its own passwords, the original keeps its");

        // Deleting a session deletes what the manager keeps for it.
        Check(g_plugin.DeleteFileW(L"\\it-imp3") != FALSE, "a session is deleted");
        Check(StoreValue(L"it-imp3") == L"(none)" && StoreValue(L"it-imp3$$jump") == L"(none)",
              "its passwords leave the password manager");

        // A file copied onto a saved session: TC is told it exists, asks,
        // and copies again with overwrite. The old passwords go with the old
        // settings.
        WriteFileBytes(local + L"in2.ini", "[x]\r\nserver=127.0.0.1:3\r\npassword=plain:secret9\r\n");
        Check(g_plugin.PutFileW((local + L"in2.ini").c_str(), L"\\it-imp2", 0) == FS_FILE_EXISTS,
              "a session file onto a saved session reports that it exists");
        Check(g_plugin.PutFileW((local + L"in2.ini").c_str(), L"\\it-imp2", FS_COPYFLAGS_OVERWRITE) == FS_FILE_OK,
              "and replaces it when told to overwrite");
        Check(StoreValue(L"it-imp2") == L"secret9" && StoreValue(L"it-imp2$$jump") == L"(none)" &&
              iniValue(L"it-imp2", L"server") == L"127.0.0.1:3",
              "the replaced session has the file's settings and passwords only");
        DeleteFileW((local + L"in2.ini").c_str());

        // A folder of sessions named with a trailing separator, as TC does
        // before copying a file into it, is listed, not connected to.
        Check(g_plugin.PutFileW((local + L"in.ini").c_str(), L"\\it-fold\\s1.ini", 0) == FS_FILE_OK,
              "a session file is copied into a folder of sessions");
        {
            WIN32_FIND_DATAW fd{};
            const HANDLE h = g_plugin.FindFirstW(L"\\it-fold\\", &fd);
            Check(h != INVALID_HANDLE_VALUE, "the folder lists with a trailing separator");
            if (h != INVALID_HANDLE_VALUE)
                g_plugin.FindClose(h);
        }
        g_plugin.DeleteFileW(L"\\it-fold\\s1");

        g_plugin.DeleteFileW(L"\\it-imp2");
        g_plugin.DeleteFileW(L"\\it-victim");
        DeleteFileW((local + L"in.ini").c_str());
        DeleteFileW((local + L"evil.ini").c_str());
        DeleteFileW(out.c_str());
        RemoveDirectoryW(local.c_str());
        Check(g_unexpectedPrompts == 0, "no unexpected prompts");
        std::printf("%d passed, %d failed, %d known\n", g_passed, g_failed, g_known);
        return g_failed == 0 ? 0 : 1;
    }

    bool listed = false;
    ListDir(root, listed);
    if (!Check(listed && g_unexpectedPrompts == 0, "connect and list " + Narrow(remoteBase)))
        return 1;

    if (mode == L"postcmd") {
        // The command's output reaches the log as whole lines, a Cyrillic
        // word at the end of one included.
        const std::wstring expect = EnvString(L"SFTP_IT_POSTCMD_EXPECT");
        bool found = false;
        for (const auto& line : g_logLines) {
            std::wstring t = line;
            while (!t.empty() && (t.back() == L'\r' || t.back() == L'\n' || t.back() == L' '))
                t.pop_back();
            if (!expect.empty() && t.size() >= expect.size() &&
                t.compare(t.size() - expect.size(), expect.size(), expect) == 0)
                found = true;
        }
        Check(found, "the post-login command's output is in the log, whole (" + Narrow(expect) + ")");
    }
    if (!Check(g_plugin.MkDirW(dir.c_str()) == TRUE, "create the run directory"))
        return 1;

    const std::wstring local = NewTempDir(L"src");
    const std::wstring back = NewTempDir(L"dst");

    struct Sample { std::wstring name; std::string content; };
    std::vector<Sample> samples = {
        {L"random.bin", RandomBytes(3000017, 1)},
        {L"empty.dat", std::string()},
        {L"zażółć gęślą jaźń.txt", "Polish name\n"},
        {L"unicode ✓ данные.txt", "outside the ANSI code page\n"},
        {L"it's a ; $(x) & `y` [z].bin", RandomBytes(70000, 2)},
    };

    std::map<std::wstring, std::string> expectedHash;
    for (const auto& s : samples) {
        WriteFileBytes(local + s.name, s.content);
        expectedHash[s.name] = Sha256File(local + s.name);
        const int rc = g_plugin.PutFileW((local + s.name).c_str(), (dir + L"\\" + s.name).c_str(), 0);
        Check(rc == FS_FILE_OK, "upload " + Narrow(s.name) + " (rc=" + std::to_string(rc) + ")");
    }

    {
        const int rc = g_plugin.PutFileW((local + samples[0].name).c_str(), (dir + L"\\" + samples[0].name).c_str(), 0);
        Check(rc == FS_FILE_EXISTS || rc == FS_FILE_EXISTSRESUMEALLOWED,
              "a second upload without overwrite reports the existing file (rc=" + std::to_string(rc) + ")");
    }

    bool ok = false;
    auto entries = ListDir(dir, ok);
    Check(ok, "list the run directory");
    for (const auto& s : samples) {
        const auto it = entries.find(s.name);
        Check(it != entries.end() && it->second.size == s.content.size(),
              "listing shows " + Narrow(s.name) + " with " + std::to_string(s.content.size()) + " bytes");
    }

    for (const auto& s : samples) {
        std::wstring target = back + s.name;
        RemoteInfoStruct ri = InfoFor(dir, s.name);
        const int rc = g_plugin.GetFileW((dir + L"\\" + s.name).c_str(), target.data(), FS_COPYFLAGS_OVERWRITE, &ri);
        Check(rc == FS_FILE_OK && Sha256File(target) == expectedHash[s.name],
              "download " + Narrow(s.name) + " is byte-identical (rc=" + std::to_string(rc) + ")");
    }

    {
        const int rc = g_plugin.RenMovFileW((dir + L"\\random.bin").c_str(), (dir + L"\\renamed.bin").c_str(), TRUE, FALSE, nullptr);
        entries = ListDir(dir, ok);
        Check(rc == FS_FILE_OK && entries.count(L"renamed.bin") && !entries.count(L"random.bin"),
              "rename random.bin to renamed.bin (rc=" + std::to_string(rc) + ")");
    }

    {
        const std::string full = RandomBytes(2000003, 3);
        WriteFileBytes(local + L"resume.bin", full.substr(0, 700001));
        g_plugin.PutFileW((local + L"resume.bin").c_str(), (dir + L"\\resume.bin").c_str(), 0);
        WriteFileBytes(local + L"resume.bin", full);
        const int rc = g_plugin.PutFileW((local + L"resume.bin").c_str(), (dir + L"\\resume.bin").c_str(), FS_COPYFLAGS_RESUME);
        if (rc == FS_FILE_NOTSUPPORTED) {
            Check(true, "resumed upload not offered in this mode");
        } else {
            std::wstring target = back + L"resume.bin";
            RemoteInfoStruct ri = InfoFor(dir, L"resume.bin");
            const int get = g_plugin.GetFileW((dir + L"\\resume.bin").c_str(), target.data(), FS_COPYFLAGS_OVERWRITE, &ri);
            Check(rc == FS_FILE_OK && get == FS_FILE_OK && Sha256File(target) == Sha256File(local + L"resume.bin"),
                  "resumed upload completes a partial file (rc=" + std::to_string(rc) + ")");
        }
    }

    {
        std::wstring target = dir + L"\\renamed.bin";
        const int rc = g_plugin.ExecuteFileW(nullptr, target.data(), L"chmod 640");
        entries = ListDir(dir, ok);
        const auto it = entries.find(L"renamed.bin");
        const DWORD mode = it != entries.end() ? (it->second.unixMode & 0777) : 0;
        char octal[8];
        std::snprintf(octal, sizeof(octal), "%03lo", static_cast<unsigned long>(mode));
        Check(rc == FS_EXEC_OK && mode == 0640, std::string("chmod 640 is reported back as ") + octal);
    }

    {
        // A missing directory is an error, an empty one an empty listing.
        bool listedMissing = true;
        ListDir(dir + L"\\no-such-dir", listedMissing);
        Check(!listedMissing, "listing a missing directory fails");
        const std::wstring emptyDir = dir + L"\\empty-dir";
        bool listedEmpty = false;
        const bool made = g_plugin.MkDirW(emptyDir.c_str()) == TRUE;
        const auto emptyEntries = ListDir(emptyDir, listedEmpty);
        Check(made && listedEmpty && emptyEntries.empty(), "an empty directory lists as empty");
        Check(g_plugin.RemoveDirW(emptyDir.c_str()) == TRUE, "remove the empty directory");
    }

    {
        // A file the server refuses to read: the download fails and leaves
        // no local file, and a local file it was to overwrite stays intact.
        // The shell paths learn of the refusal only after the local file
        // exists: they remove an empty one, but an overwritten copy is gone
        // (open in TODO).
        const std::wstring name = L"unreadable.bin";
        WriteFileBytes(local + name, RandomBytes(5000, 4));
        g_plugin.PutFileW((local + name).c_str(), (dir + L"\\" + name).c_str(), 0);
        std::wstring remote = dir + L"\\" + name;
        const int chmod = g_plugin.ExecuteFileW(nullptr, remote.data(), L"chmod 000");
        Check(chmod == FS_EXEC_OK, "chmod 000 on " + Narrow(name));

        std::wstring target = back + name;
        DeleteFileW(target.c_str());
        RemoteInfoStruct ri = InfoFor(dir, name);
        const int messagesBefore = g_messages;
        int rc = g_plugin.GetFileW(remote.c_str(), target.data(), 0, &ri);
        const std::string fresh = "download of an unreadable file fails, no local file left (rc=" + std::to_string(rc) + ")";
        Check(rc != FS_FILE_OK && !LocalExists(target), fresh);

        WriteFileBytes(target, "previous local copy");
        const std::string keepHash = Sha256File(target);
        rc = g_plugin.GetFileW(remote.c_str(), target.data(), FS_COPYFLAGS_OVERWRITE, &ri);
        const std::string over = "overwrite from an unreadable file keeps the local copy (rc=" + std::to_string(rc) + ")";
        if (shellMode)
            Known(rc != FS_FILE_OK && Sha256File(target) == keepHash, over);
        else
            Check(rc != FS_FILE_OK && Sha256File(target) == keepHash, over);
        // Total Commander reports the failed download itself; the plugin
        // adds no dialog of its own, least of all one blaming scp.
        Check(g_messages == messagesBefore, "no extra message box for an unreadable file");
        DeleteFileW(target.c_str());
        g_plugin.ExecuteFileW(nullptr, remote.data(), L"chmod 644");
    }

    if (textChecks) {
        // CRLF pairs straddle every chunk boundary the transfer code uses.
        std::string crlf;
        while (crlf.size() < 1500000)
            crlf += "line of text " + std::to_string(crlf.size()) + "\r\n";
        std::string lf;
        for (char c : crlf)
            if (c != '\r') lf += c;
        WriteFileBytes(local + L"text.txt", crlf);
        // Total Commander selects the transfer mode through this verb.
        std::wstring modeTarget = dir;
        g_plugin.ExecuteFileW(nullptr, modeTarget.data(), L"mode A");
        const int up = g_plugin.PutFileW((local + L"text.txt").c_str(), (dir + L"\\text.txt").c_str(), 0);
        entries = ListDir(dir, ok);
        const auto it = entries.find(L"text.txt");
        Check(up == FS_FILE_OK && it != entries.end() && it->second.size == lf.size(),
              "text upload stores LF line ends (" + std::to_string(lf.size()) + " bytes)");
        std::wstring target = back + L"text.txt";
        RemoteInfoStruct ri = InfoFor(dir, L"text.txt");
        const int get = g_plugin.GetFileW((dir + L"\\text.txt").c_str(), target.data(), FS_COPYFLAGS_OVERWRITE, &ri);
        Check(get == FS_FILE_OK && Sha256File(target) == Sha256File(local + L"text.txt"),
              "text download restores CRLF line ends");
        g_plugin.ExecuteFileW(nullptr, modeTarget.data(), L"mode I");
    }

    if (mode == L"nosub") {
        const std::wstring restart = EnvString(L"SFTP_IT_RESTART_CMD");
        if (!restart.empty()) {
            // The server goes away under the open session; the next request
            // has to reconnect, and on this server only the server command
            // can start SFTP.
            const int rc = _wsystem(restart.c_str());
            Check(rc == 0, "restart the server (rc=" + std::to_string(rc) + ")");
            bool again = false;
            for (int attempt = 0; attempt < 3 && !again; ++attempt) {
                if (attempt)
                    Sleep(2000);
                ListDir(dir, again);
            }
            Check(again, "after a server restart the session reconnects through the server command");
        }
    }

    if (mode == L"sftp") {
        // Two background transfers on the session, overlapping the way TC
        // runs them: each opens its own connection at START and closes it
        // at END. The first to end must not close the other's connection
        // (still in use) or the panel's (still open).
        HANDLE aListed = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        HANDLE bListed = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        HANDLE aEnded = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        bool okA = false, okB1 = false, okB2 = false;
        std::thread a([&] {
            g_plugin.StatusInfoW(dir.c_str(), FS_STATUS_START, FS_STATUS_OP_GET_MULTI_THREAD);
            ListDir(dir, okA);
            SetEvent(aListed);
            WaitForSingleObject(bListed, 60000);
            g_plugin.StatusInfoW(dir.c_str(), FS_STATUS_END, FS_STATUS_OP_GET_MULTI_THREAD);
            SetEvent(aEnded);
        });
        std::thread b([&] {
            WaitForSingleObject(aListed, 60000);
            g_plugin.StatusInfoW(dir.c_str(), FS_STATUS_START, FS_STATUS_OP_GET_MULTI_THREAD);
            ListDir(dir, okB1);
            SetEvent(bListed);
            WaitForSingleObject(aEnded, 60000);
            const int connects = CountConnects();
            ListDir(dir, okB2);
            okB2 = okB2 && CountConnects() == connects;
            g_plugin.StatusInfoW(dir.c_str(), FS_STATUS_END, FS_STATUS_OP_GET_MULTI_THREAD);
        });
        a.join();
        b.join();
        CloseHandle(aListed);
        CloseHandle(bListed);
        CloseHandle(aEnded);
        Check(okA && okB1, "two background transfers list the directory");
        Check(okB2, "a background transfer keeps its connection when another one ends (no reconnect)");
        const int connectsBefore = CountConnects();
        bool okMain = false;
        ListDir(dir, okMain);
        Check(okMain && CountConnects() == connectsBefore,
              "the panel's connection survives background transfers ending (no reconnect)");
    }

    // Cleanup: only what this run created.
    entries = ListDir(dir, ok);
    for (const auto& e : entries)
        Check(g_plugin.DeleteFileW((dir + L"\\" + e.first).c_str()) == TRUE, "delete " + Narrow(e.first));
    Check(g_plugin.RemoveDirW(dir.c_str()) == TRUE, "remove the run directory");
    auto rootEntries = ListDir(root, ok);
    Check(ok && !rootEntries.count(runName), "the run directory is gone");

    const std::string sessionRoot = "\\" + Narrow(session);
    g_plugin.Disconnect(sessionRoot.c_str());
    Check(g_unexpectedPrompts == 0, "no unexpected prompts");

    std::printf("%d passed, %d failed, %d known\n", g_passed, g_failed, g_known);
    return g_failed == 0 ? 0 : 1;
}
