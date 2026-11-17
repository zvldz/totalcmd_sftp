#include "global.h"
#include <windows.h>
#include <ws2tcpip.h>
#include <shellapi.h>
#include <stdio.h>
#include <array>
#include <string>
#include <format>
#include "SftpClient.h"
#include "PluginEntryPoints.h"
#include "fsplugin.h"
#include "ServerRegistry.h"
#include "res/resource.h"
#include "CoreUtils.h"
#include "SftpInternal.h"
#include "PpkConverter.h"
#include "UnicodeHelpers.h"

#define AUTH_LOG(fmt, ...) SFTP_LOG("AUTH", fmt, ##__VA_ARGS__)

extern "C"
void kbd_callback(LPCSTR name, int name_len,
                  LPCSTR instruction, int instruction_len, int num_prompts,
                  const LIBSSH2_USERAUTH_KBDINT_PROMPT * prompts,
                  LIBSSH2_USERAUTH_KBDINT_RESPONSE * responses,
                  LPVOID * abstract)
{
    std::array<char, 1024> buf{};
    std::array<char, 256> retbuf{};
    pConnectSettings ConnectSettings = static_cast<pConnectSettings>(*abstract);

    for (int i = 0; i < num_prompts; i++) {
        // Pass the stored password as the first response for password-like prompts.
        // Multiple callback invocations are tracked via InteractivePasswordSent.
        const size_t copyLen = min(static_cast<size_t>(prompts[i].length), retbuf.size() - 1);
        memcpy(retbuf.data(), prompts[i].text, copyLen);
        retbuf[copyLen] = '\0';
        ShowStatus(retbuf.data());
        _strlwr_s(retbuf.data(), retbuf.size());
        const bool passwordPrompt = PromptLooksLikePasswordRequest(retbuf.data());
        bool autoSendPassword = passwordPrompt && ConnectSettings &&
                                !ConnectSettings->account_password.empty() &&
                                !ConnectSettings->InteractivePasswordSent;
        if (autoSendPassword) {
            ConnectSettings->InteractivePasswordSent = true;
            responses[i].text = _strdup(ConnectSettings->account_password.c_str());
            if (responses[i].text) {
                responses[i].length = (unsigned int)strlen(responses[i].text);
                ShowStatusId(IDS_LOG_SEND_STORED_PASS, nullptr, true);
            } else {
                autoSendPassword = false;
            }
        }
        if (!autoSendPassword) {
            std::string promptMsg;
            if (instruction && instruction_len)
                promptMsg = std::string(instruction, instruction_len) + "\n";
            if (prompts[i].length && prompts[i].text)
                promptMsg += std::string(reinterpret_cast<LPCSTR>(prompts[i].text), prompts[i].length);
            if (promptMsg.empty())
                promptMsg = "Password:";

            std::string title;
            if (name && name_len)
                title.assign(name, static_cast<size_t>(name_len));
            else
                title = "SFTP password for";
            if (ConnectSettings)
                title = std::format("{} {}@{}", title, ConnectSettings->user, ConnectSettings->server);
            retbuf[0] = 0;

            ShowStatusId(IDS_LOG_REQUEST_PASS, nullptr, true);
            const bool answered = RequestProcI(PluginNumber, RT_Password, title.c_str(), promptMsg.c_str(),
                                               retbuf.data(), retbuf.size()-1) != 0;
            if (ConnectSettings)
                ConnectSettings->authPromptDone = get_sys_ticks();
            if (answered) {
                responses[i].text = _strdup(retbuf.data());
                responses[i].length = (unsigned int)strlen(retbuf.data());
                // Kept for background transfers and reconnects once the
                // login succeeds (CommitTypedPassword); until then it is not
                // offered again, so a mistyped one is asked for anew. Only an
                // answer to a password prompt: a one-time code kept here
                // would be replayed as the password next time.
                if (passwordPrompt && ConnectSettings)
                    ConnectSettings->typed_password = retbuf.data();
                ShowStatusId(IDS_LOG_SEND_USER_PASS, nullptr, true);
            } else {
                responses[i].text = nullptr;
                responses[i].length = 0;
            }
            SecureZeroMemory(retbuf.data(), retbuf.size());
        }
    }
} /* kbd_callback */

static bool ismimechar(const char ch)
{
    return ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
             ch == '/' || ch == '+' || ch == '=' || ch == '\r' || ch == '\n');
}

static bool EndsWithNoCase(LPCSTR text, LPCSTR suffix) noexcept
{
    if (!text || !suffix)
        return false;
    size_t tlen = strlen(text);
    size_t slen = strlen(suffix);
    if (tlen < slen)
        return false;
    return _stricmp(text + tlen - slen, suffix) == 0;
}

static void ShowPpkConversionFailure(PpkConvertError convErr)
{
    switch (convErr) {
    case PpkConvertError::unsupported_version:
        ShowStatusId(IDS_LOG_PPK_ERR_VERSION, nullptr, true);
        break;
    case PpkConvertError::unsupported_algorithm:
        ShowStatusId(IDS_LOG_PPK_ERR_ALGO, nullptr, true);
        break;
    case PpkConvertError::unsupported_encryption:
    case PpkConvertError::unsupported_kdf:
        ShowStatusId(IDS_LOG_PPK_ERR_ENC, nullptr, true);
        break;
    case PpkConvertError::kdf_unavailable:
        ShowStatusId(IDS_LOG_PPK_ERR_ARGON2, nullptr, true);
        break;
    case PpkConvertError::kdf_limits_exceeded:
        ShowStatusId(IDS_LOG_PPK_ERR_LIMITS, nullptr, true);
        break;
    case PpkConvertError::inconsistent_key:
        ShowStatusId(IDS_LOG_PPK_ERR_INCONSISTENT, nullptr, true);
        break;
    case PpkConvertError::passphrase_required:
    case PpkConvertError::bad_passphrase_or_mac:
        ShowStatusId(IDS_LOG_PPK_ERR_PASSPHRASE, nullptr, true);
        break;
    default:
        ShowStatusId(IDS_LOG_PPK_ERR_GENERIC, nullptr, true);
        break;
    }
}

static void ExpandAuthPath(char* path, size_t pathLen, LPCSTR user)
{
    if (!path || pathLen == 0)
        return;
    ReplaceSubString(path, "%USER%", user ? user : "", pathLen - 1);
    ReplaceEnvVars(path, pathLen - 1);
}

bool KeyFileHoldsPrivateKey(const std::string& path, const std::string& user)
{
    if (path.empty())
        return false;
    std::array<char, 1024> expanded{};
    strlcpy(expanded.data(), path.c_str(), expanded.size() - 1);
    ExpandAuthPath(expanded.data(), expanded.size(), user.c_str());

    handle_util::FileHandle hf(CreateFileW(unicode_util::internal_to_wide(expanded.data()).c_str(),
        GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!hf)
        return false;

    // Every private format the plugin takes says so in its opening line —
    // "...PRIVATE KEY-----" for OpenSSH and PEM, "PuTTY-User-Key-File-" for
    // PPK — and no public one does.
    std::array<char, 512> head{};
    DWORD got = 0;
    if (!ReadFile(hf.get(), head.data(), static_cast<DWORD>(head.size() - 1), &got, nullptr))
        return false;
    const std::string_view text(head.data(), got);
    return text.find("PRIVATE KEY-----") != std::string_view::npos ||
           text.find("PuTTY-User-Key-File-") != std::string_view::npos;
}

static bool DetectPrivateKeyEncrypted(LPCSTR privkeyfile, bool* outEncrypted)
{
    if (!privkeyfile || !outEncrypted)
        return false;

    DWORD dwShareMode = FILE_SHARE_READ | FILE_SHARE_WRITE;
    DWORD dwFlags = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN;
    handle_util::FileHandle hf(CreateFileW(unicode_util::internal_to_wide(privkeyfile).c_str(),
        GENERIC_READ, dwShareMode, nullptr, OPEN_EXISTING, dwFlags, nullptr));
    if (!hf)
        return false;

    std::array<char, 1024> filebuf{};
    DWORD dataread = 0;
    bool isencrypted = true;
    if (ReadFile(hf.get(), filebuf.data(), static_cast<DWORD>(filebuf.size() - 32), &dataread, nullptr)) {
        filebuf[dataread] = 0;
        LPSTR p = strchr(filebuf.data(), '\n');
        if (!p)
            p = strchr(filebuf.data(), '\r');
        if (p) {
            p++;
            while (p[0] == '\r' || p[0] == '\n')
                p++;
            isencrypted = false;
            for (int i = 0; i < 32; i++)
                if (!ismimechar(p[i]))
                    isencrypted = true;
            if (!isencrypted) {
                char* p2 = filebuf.data();
                while (p2[0] == '\r' || p2[0] == '\n')
                    p2++;
                if (strncmp(p2, "-----BEGIN OPENSSH PRIVATE KEY-----", 35) == 0) {
                    std::array<char, 64> outbuf{};
                    int len = MimeDecode(p, min(64, strlen(p)), outbuf.data(), outbuf.size());
                    for (int i = 0; i < len - 6; i++) {
                        if (outbuf[i] == 'b' && strncmp(outbuf.data() + i, "bcrypt", 6) == 0) {
                            isencrypted = true;
                            break;
                        }
                    }
                }
            }
        }
    }
    *outEncrypted = isencrypted;
    return true;
}

static void BuildUserAtServerTitle(char* out, size_t outLen, int prefixResId,
                                   LPCSTR user, LPCSTR host)
{
    if (!out || outLen == 0)
        return;
    out[0] = 0;
    LoadStr(out, outLen, prefixResId);
    strlcat(out, user ? user : "", outLen - 1);
    strlcat(out, "@", outLen - 1);
    strlcat(out, host ? host : "", outLen - 1);
}

// The whole key file at `path` (an internal string). Key files are small;
// anything past 1 MB is not one.
static bool ReadKeyFile(const char* path, std::string& out)
{
    handle_util::FileHandle hf(CreateFileW(unicode_util::internal_to_wide(path).c_str(),
        GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
    if (!hf)
        return false;
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(hf.get(), &size) || size.QuadPart <= 0 || size.QuadPart > 1024 * 1024)
        return false;
    out.assign(static_cast<size_t>(size.QuadPart), '\0');
    DWORD got = 0;
    if (!ReadFile(hf.get(), out.data(), static_cast<DWORD>(out.size()), &got, nullptr)) {
        SecureZeroMemory(out.data(), out.size());
        out.clear();
        return false;
    }
    out.resize(got);
    return !out.empty();
}

// A key passphrase reaches us as typed, in UTF-8. Windows tools encrypt with
// the passphrase in the system codepage instead (puttygen reads it with
// GetWindowTextA, characters outside the codepage turned into '?'), tools
// elsewhere in UTF-8. A passphrase with characters beyond ASCII is therefore
// tried in both forms; one in ASCII is the same bytes either way.
static bool HasNonAscii(const char* s) noexcept
{
    for (; s && *s; ++s)
        if (static_cast<unsigned char>(*s) >= 0x80)
            return true;
    return false;
}

static bool ConvertPpkInEitherEncoding(const char* ppkPath, const char* passphrase,
                                       std::string& outPem, PpkConvertError* outError)
{
    bool converted = ConvertPpkToOpenSsh(ppkPath, passphrase, outPem, outError);
    if (!converted && *outError == PpkConvertError::bad_passphrase_or_mac && HasNonAscii(passphrase)) {
        std::string acp = unicode_util::internal_to_acp(passphrase);
        converted = ConvertPpkToOpenSsh(ppkPath, acp.c_str(), outPem, outError);
        SecureZeroMemory(acp.data(), acp.size());
        AUTH_LOG("PPK conversion with the passphrase in the system codepage: converted=%d", converted);
    }
    return converted;
}

// Whether a PuTTY key file is protected by a passphrase: its header names
// the cipher, "none" when it is not.
static bool PpkIsEncrypted(const char* ppkPath)
{
    std::string text;
    if (!ReadKeyFile(ppkPath, text))
        return false;
    const size_t at = text.find("Encryption:");
    const bool encrypted = at != std::string::npos &&
                           text.compare(at + 11, 5, " none") != 0;
    SecureZeroMemory(text.data(), text.size());
    return encrypted;
}

// A PuTTY key is converted in memory into `outConvertedPem`; its public half
// is then derived from it, so the public key file is dropped.
static bool PreparePrivateKeyForAuth(
    LPCSTR user,
    LPCSTR host,
    std::string& keyPassphrase,
    const char* privKeyFile,
    char** ioPubKeyPtr,
    bool* outConverted,
    std::string& outConvertedPem,
    char* ioPromptBuf,
    size_t ioPromptBufLen)
{
    if (!privKeyFile || !ioPubKeyPtr || !outConverted || !ioPromptBuf)
        return false;
    if (!EndsWithNoCase(privKeyFile, ".ppk"))
        return true;

    const char* ppkPass = keyPassphrase.c_str();
    PpkConvertError convErr = PpkConvertError::internal_error;
    ShowStatusId(IDS_LOG_PPK_CONVERTING, nullptr, true);
    bool converted = ConvertPpkInEitherEncoding(privKeyFile, ppkPass, outConvertedPem, &convErr);
    const std::string convStatus = std::format("PPK conv: {}, err={}", converted, static_cast<int>(convErr));
    AUTH_LOG("PPK conversion: converted=%d, convErr=%d", converted, convErr);
    ShowStatus(convStatus.c_str());

    if (!converted && (convErr == PpkConvertError::passphrase_required ||
                       convErr == PpkConvertError::bad_passphrase_or_mac)) {
        std::array<char, 250> title{};
        std::array<char, 256> ppkPassBuf{};
        title[0] = 0;
        ppkPassBuf[0] = 0;
        LoadStr(ioPromptBuf, ioPromptBufLen, IDS_KEYPASSPHRASE);
        BuildUserAtServerTitle(title.data(), title.size(), IDS_PASSPHRASE, user, host);
        if (RequestProcI(PluginNumber, RT_Password, title.data(), ioPromptBuf, ppkPassBuf.data(), ppkPassBuf.size() - 1)) {
            converted = ConvertPpkInEitherEncoding(privKeyFile, ppkPassBuf.data(), outConvertedPem, &convErr);
            // This prompt is only reached once the passphrase already held
            // failed to open the key, so a conversion that succeeds here
            // replaces it: what opened the key outranks what was assumed.
            if (converted)
                keyPassphrase = ppkPassBuf.data();
        }
        SecureZeroMemory(ppkPassBuf.data(), ppkPassBuf.size());
    }

    if (!converted) {
        ShowPpkConversionFailure(convErr);
        return false;
    }

    *ioPubKeyPtr = nullptr;
    *outConverted = true;
    return true;
}

static bool ValidatePublicKeyFileIfPresent(
    char* pubkeyfileptr,
    LPCSTR pubkeyfile,
    DWORD dwShareMode,
    DWORD dwFlags)
{
    if (!pubkeyfileptr || !pubkeyfile[0])
        return true;

    DWORD dataread = 0;
    std::array<char, 1024> filebuf{};
    handle_util::FileHandle hf(CreateFileW(unicode_util::internal_to_wide(pubkeyfile).c_str(),
        GENERIC_READ, dwShareMode, nullptr, OPEN_EXISTING, dwFlags, nullptr));
    if (!hf) {
        ShowStatusId(IDS_ERR_LOAD_PUBKEY, pubkeyfile, true);
        return false;
    }

    if (ReadFile(hf.get(), filebuf.data(), 35, &dataread, nullptr)) {
        if (_strnicmp(filebuf.data(), "ssh-", 4) != 0 &&
            _strnicmp(filebuf.data(), "ecdsa-", 6) != 0 &&
            _strnicmp(filebuf.data(), "-----BEGIN OPENSSH PRIVATE KEY-----", 35) != 0 &&
            _strnicmp(filebuf.data(), "-----BEGIN RSA PRIVATE KEY-----", 31) != 0 &&
            _strnicmp(filebuf.data(), "-----BEGIN EC PRIVATE KEY-----", 30) != 0)
        {
            ShowStatusId(IDS_ERR_PUBKEY_WRONG_FORMAT, nullptr, true);
            return false;
        }
    }
    return true;
}


int SftpAuthPageantOn(const SshAuthTarget& target, LPCSTR progressbuf, int progress, int * ploop, SYSTICKS * plasttime, int * auth_pw)
{
    std::array<char, 1024> buf{};
    struct libssh2_agent_publickey * identity = nullptr;
    struct libssh2_agent_publickey * prev_identity = nullptr;

    std::unique_ptr<ISshAgent> agent = target.session->agentInit();
    auto finish = [&](int code) -> int {
        if (code < 0) {
            ShowStatusId(-code, nullptr, true);
        } else if (code == 0) {
            ShowStatusId(IDS_AGENT_AUTHSUCCEEDED, nullptr, true);
        }
        if (agent) {
            agent->disconnect();
        }
        return code;
    };

    if (!agent || agent->connect() != 0) {
        if (agent) {
            agent->disconnect();
            // ~Libssh2Agent() calls libssh2_agent_free()
            agent.reset();
        }
        // Attempt to launch Pageant.
        // A pageant.lnk beside the plugin starts it; wide paths, so a plugin
        // folder the system codepage cannot spell works too.
        std::vector<wchar_t> modulePath(32768);
        const DWORD len = GetModuleFileNameW(hinst, modulePath.data(), static_cast<DWORD>(modulePath.size()));
        if (len == 0 || len >= modulePath.size())
            return finish(-IDS_AGENT_CONNECTERROR);
        std::wstring dirname(modulePath.data(), len);
        const size_t slash = dirname.find_last_of(L'\\');
        dirname.resize(slash == std::wstring::npos ? 0 : slash + 1);
        const std::wstring linkname = dirname + L"pageant.lnk";
        if (GetFileAttributesW(linkname.c_str()) == INVALID_FILE_ATTRIBUTES)
            return finish(-IDS_AGENT_CONNECTERROR);

        HWND active = GetForegroundWindow();
        ShellExecuteW(active, nullptr, linkname.c_str(), nullptr, dirname.c_str(), SW_SHOW);
        Sleep(PAGEANT_WAIT_MS);
        SYSTICKS starttime = get_sys_ticks();
        while (active != GetForegroundWindow() && get_ticks_between(starttime) < PAGEANT_TIMEOUT_MS) {
            Sleep(200);
            if (ProgressLoop(progressbuf, progress, progress + 5, ploop, plasttime))
                break;
        }
        agent = target.session->agentInit();
        if (!agent)
            return finish(-IDS_AGENT_CONNECTERROR);
        int rc = agent->connect();
        if (rc)
            return finish(-IDS_AGENT_CONNECTERROR);
    }

    int rc = agent->listIdentities();
    if (rc)
        return finish(-IDS_AGENT_REQUESTIDENTITIES);
    while (1) {
        int auth = agent->getIdentity(&identity, prev_identity);
        if (auth == 1)
            return finish(-IDS_AGENT_AUTHFAILED);  /* pub key */
        if (auth < 0)
            return finish(-IDS_AGENT_NOIDENTITY);
        std::array<char, 128> str1{}, str2{}, str3{};
        LoadStr(str1, IDS_AGENT_TRYING1);
        LoadStr(str2, IDS_AGENT_TRYING2);
        LoadStr(str3, IDS_AGENT_TRYING3);
        ShowStatus((std::string(str1.data()) + target.user + str2.data() + identity->comment + str3.data()).c_str());
        const SYSTICKS authStart = get_sys_ticks();
        while ((auth = agent->userauth(target.user.c_str(), identity)) == LIBSSH2_ERROR_EAGAIN) {
            if (ProgressLoop(progressbuf, progress, progress + 5, ploop, plasttime))
                return finish(-IDS_AGENT_AUTHFAILED);
            if (get_ticks_between(authStart) > SSH_AUTH_STAGE_TIMEOUT_MS) {
                ShowStatusId(IDS_LOG_PAGEANT_TIMEOUT, nullptr, true);
                return finish(-IDS_AGENT_AUTHFAILED);
            }
            if (target.waitIo) target.waitIo();
        }
        if (auth == 0)
            return finish(0);   /* OK */
        prev_identity = identity;
    }
}

// Bind the agent flow to the target server.
int SftpAuthPageant(pConnectSettings ConnectSettings, LPCSTR progressbuf, int progress, int * ploop, SYSTICKS * plasttime, int * auth_pw)
{
    SshAuthTarget target;
    target.session  = ConnectSettings->session.get();
    target.host     = ConnectSettings->server;
    target.user     = ConnectSettings->user;
    target.password = &ConnectSettings->account_password;
    target.keyPassphrase = &ConnectSettings->key_passphrase;
    target.waitIo   = [ConnectSettings]() { WaitForSshIo(ConnectSettings); };
    return SftpAuthPageantOn(target, progressbuf, progress, ploop, plasttime, auth_pw);
}

int SftpAuthPubKeyOn(const SshAuthTarget& target, LPCSTR progressbuf, int progress, int * ploop, SYSTICKS * plasttime, int * auth_pw, AuthFailureUi onFailure)
{
    // Both secrets are dereferenced throughout; a caller that leaves either
    // unset fails here instead of faulting further in.
    if (!target.password || !target.keyPassphrase)
        return -IDS_ERR_AUTH_PUBKEY;

    std::array<char, 1024> buf{};
    std::array<char, 256> passphrase{};
    // UTF-8 paths: room for a long or non-Latin one after %USER% and
    // environment expansion.
    std::array<char, 1024> pubkeyfile{};
    std::array<char, 1024> privkeyfile{};
    bool convertedPpk = false;
    std::string convertedPem;     // a PuTTY key converted in memory
    std::string privData;         // what goes to libssh2
    std::string pubData;
    char* pubkeyfileptr = pubkeyfile.data();
    auto cleanupConvertedIfNeeded = [&]() {
        for (std::string* k : { &convertedPem, &privData, &pubData }) {
            if (!k->empty())
                SecureZeroMemory(k->data(), k->size());
            k->clear();
        }
    };
    auto clearPassphrase = [&]() {
        SecureZeroMemory(passphrase.data(), passphrase.size());
    };

    AUTH_LOG("=== SftpAuthPubKey START (host=%s) ===", target.host.c_str());
    // Check if LogProc is available
    extern tLogProc LogProc;
    LogProcI(PluginNumber, MSGTYPE_DETAILS, "=== SftpAuthPubKey ===");
    AUTH_LOG("privkeyfile=%s", target.privkeyfile.c_str());
    AUTH_LOG("pubkeyfile=%s", target.pubkeyfile.c_str());
    AUTH_LOG("password_empty=%d", target.password->empty() ? 1 : 0);
    AUTH_LOG("host=%s", target.host.c_str());
    AUTH_LOG("user=%s", target.user.c_str());

    // A path that does not fit is refused rather than cut to another one.
    if (target.pubkeyfile.size() >= pubkeyfile.size() - 1 ||
        target.privkeyfile.size() >= privkeyfile.size() - 1) {
        ShowStatusId(IDS_ERR_LOAD_PRIVKEY, target.privkeyfile.c_str(), true);
        clearPassphrase();
        return -LIBSSH2_ERROR_FILE;
    }
    strlcpy(pubkeyfile.data(), target.pubkeyfile.c_str(), pubkeyfile.size()-1);
    ExpandAuthPath(pubkeyfile.data(), pubkeyfile.size(), target.user.c_str());
    strlcpy(privkeyfile.data(), target.privkeyfile.c_str(), privkeyfile.size()-1);
    ExpandAuthPath(privkeyfile.data(), privkeyfile.size(), target.user.c_str());

    AUTH_LOG("After expand: privkeyfile=%s", privkeyfile.data());
    AUTH_LOG("After expand: pubkeyfile=%s", pubkeyfile.data());
    const auto keyFileExists = [](const char* p) {
        return GetFileAttributesW(unicode_util::internal_to_wide(p).c_str()) != INVALID_FILE_ATTRIBUTES;
    };
    AUTH_LOG("privkeyfile exists=%d", keyFileExists(privkeyfile.data()));

    // Fail-fast on explicit key paths that do not exist.
    if (privkeyfile.data()[0] && !keyFileExists(privkeyfile.data())) {
        ShowStatusId(IDS_ERR_LOAD_PRIVKEY, privkeyfile.data(), true);
        clearPassphrase();
        return -LIBSSH2_ERROR_FILE;
    }
    if (pubkeyfileptr && pubkeyfile.data()[0] && !keyFileExists(pubkeyfile.data())) {
        ShowStatusId(IDS_ERR_LOAD_PUBKEY, pubkeyfile.data(), true);
        clearPassphrase();
        return -LIBSSH2_ERROR_FILE;
    }

    if (!PreparePrivateKeyForAuth(target.user.c_str(), target.host.c_str(), *target.keyPassphrase,
                                  privkeyfile.data(), &pubkeyfileptr,
                                  &convertedPpk, convertedPem,
                                  buf.data(), buf.size())) {
        clearPassphrase();
        return -LIBSSH2_ERROR_FILE;
    }

    passphrase[0] = 0;
    // verify that we have a valid public key file (optional when private key is enough)
    DWORD dwShareMode = FILE_SHARE_READ | FILE_SHARE_WRITE;
    DWORD dwFlags = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN;
    if (!ValidatePublicKeyFileIfPresent(pubkeyfileptr, pubkeyfile.data(), dwShareMode, dwFlags))
    {
        clearPassphrase();
        return -LIBSSH2_ERROR_FILE;
    }

    // Skip passphrase prompt for unencrypted keys.
    // Converted PPK output PEM is unencrypted.
    bool isencrypted = true;  // Assume encrypted by default
    bool skipEncryptionCheck = convertedPpk;  // Converted PPK -> skip check, we know it's unencrypted
    
    if (!skipEncryptionCheck) {
        if (!DetectPrivateKeyEncrypted(privkeyfile.data(), &isencrypted)) {
            cleanupConvertedIfNeeded();
            ShowStatusId(IDS_ERR_LOAD_PRIVKEY, privkeyfile.data(), true);
            clearPassphrase();
            return -LIBSSH2_ERROR_FILE;
        }
    } else {
        // Converted from PPK; encryption is already known.
        isencrypted = false;
    }
    
    const std::string encStatus = std::format("Key: {}", isencrypted ? "encrypted" : "unencrypted");
    AUTH_LOG("Encryption check result: %s", encStatus.c_str());
    ShowStatus(encStatus.c_str());
    if (isencrypted) {
        AUTH_LOG("Key is encrypted, requesting passphrase");
        std::array<char, 250> title{};
        BuildUserAtServerTitle(title.data(), title.size(), IDS_PASSPHRASE, target.user.c_str(), target.host.c_str());
        LoadStr(buf, IDS_KEYPASSPHRASE);
        if (!target.keyPassphrase->empty()) {
            AUTH_LOG("Using stored passphrase");
            strlcpy(passphrase.data(), target.keyPassphrase->c_str(), passphrase.size()-1);
        } else {
            AUTH_LOG("No stored passphrase, requesting from user");
            RequestProcI(PluginNumber, RT_Password, title.data(), buf.data(), passphrase.data(), passphrase.size()-1);
        }
    } else {
        AUTH_LOG("Key is NOT encrypted, no passphrase needed");
    }

    ShowStatusId(IDS_AUTH_PUBKEY_FOR, target.user.c_str(), true);

    // No public key when the user left the field blank or pointed both
    // fields at the same file: libssh2 then derives it from the private one.
    if (pubkeyfileptr && (pubkeyfile.data()[0] == 0 ||
                          _stricmp(pubkeyfile.data(), privkeyfile.data()) == 0))
        pubkeyfileptr = nullptr;

    // The key files are read here and handed to libssh2 in memory: its own
    // file reading goes through fopen, which takes ANSI paths only.
    if (convertedPpk)
        privData.swap(convertedPem);
    else if (!ReadKeyFile(privkeyfile.data(), privData)) {
        ShowStatusId(IDS_ERR_LOAD_PRIVKEY, privkeyfile.data(), true);
        cleanupConvertedIfNeeded();
        clearPassphrase();
        return -LIBSSH2_ERROR_FILE;
    }
    if (pubkeyfileptr && !ReadKeyFile(pubkeyfile.data(), pubData)) {
        ShowStatusId(IDS_ERR_LOAD_PUBKEY, pubkeyfile.data(), true);
        cleanupConvertedIfNeeded();
        clearPassphrase();
        return -LIBSSH2_ERROR_FILE;
    }

    LoadStr(buf, IDS_AUTH_PUBKEY);
    int auth;
    const char* passphrasePtr = isencrypted ? passphrase.data() : nullptr;
    AUTH_LOG("Calling userauthPubkeyFromMemory: priv=%s pub=%s passphrase=%s",
             convertedPpk ? "(converted PPK)" : privkeyfile.data(),
             pubkeyfileptr ? pubkeyfileptr : "(null)",
             passphrasePtr ? "(set)" : "(null)");
    const auto tryKey = [&](const char* keyPass) {
        int rc;
        const SYSTICKS authStart = get_sys_ticks();
        while ((rc = target.session->userauthPubkeyFromMemory(target.user.c_str(), (unsigned)target.user.size(),
                    pubData.data(), pubData.size(), privData.data(), privData.size(), keyPass)) == LIBSSH2_ERROR_EAGAIN) {
            if (ProgressLoop(buf.data(), progress, progress + 10, ploop, plasttime))
                break;
            if (get_ticks_between(authStart) > SSH_AUTH_STAGE_TIMEOUT_MS) {
                ShowStatusId(IDS_LOG_PUBKEY_TIMEOUT, nullptr, true);
                rc = LIBSSH2_ERROR_TIMEOUT;
                break;
            }
            if (target.waitIo) target.waitIo();
        }
        return rc;
    };
    auth = tryKey(passphrasePtr);
    AUTH_LOG("userauthPubkeyFromMemory result=%d", auth);
    // A PuTTY key opened during conversion, with the passphrase held, when
    // its header names a cipher.
    bool keyOpenedWithPassphrase = convertedPpk && !target.keyPassphrase->empty() &&
                                   PpkIsEncrypted(privkeyfile.data());
    // A key that would not open with the passphrase as typed (both errors are
    // raised while reading the key, before the server is asked) gets the same
    // passphrase in the system codepage, as Windows tools encrypt with it.
    if ((auth == LIBSSH2_ERROR_KEYFILE_AUTH_FAILED || auth == LIBSSH2_ERROR_FILE) &&
        passphrasePtr && HasNonAscii(passphrasePtr)) {
        std::string acp = unicode_util::internal_to_acp(passphrasePtr);
        auth = tryKey(acp.c_str());
        SecureZeroMemory(acp.data(), acp.size());
        AUTH_LOG("userauthPubkeyFromMemory with the passphrase in the system codepage: result=%d", auth);
    }
    // Both errors are raised while reading the key, before the server is
    // asked; anything else means the passphrase opened it.
    if (isencrypted && passphrasePtr && passphrasePtr[0] &&
        auth != LIBSSH2_ERROR_KEYFILE_AUTH_FAILED && auth != LIBSSH2_ERROR_FILE)
        keyOpenedWithPassphrase = true;
    if (target.keyOpened)
        *target.keyOpened = keyOpenedWithPassphrase;
    if (auth) {
        cleanupConvertedIfNeeded();
        char* errMsg = nullptr;
        int errLen = 0;
        target.session->lastError(&errMsg, &errLen, false);
        SftpLogLastError("libssh2_userauth_publickey_frommemory: ", auth);
        std::array<char, 1024> loadedMsg{};
        LoadStr(loadedMsg, IDS_ERR_AUTH_PUBKEY);
        std::string uiMsg;
        if (loadedMsg[0] == 0 || _stricmp(loadedMsg.data(), "Error:") == 0 || strstr(loadedMsg.data(), "%s"))
            uiMsg = "Error: Authentication by client certificate failed!";
        else
            uiMsg = loadedMsg.data();
        if (errMsg && errMsg[0])
            uiMsg += "\n" + std::string(errMsg);
        // Stay quiet when the caller still has methods to try, or when it
        // asked to report failures without a dialog.
        const bool hasFallbackAuth =
            auth_pw && ((*auth_pw & SSH_AUTH_PASSWORD) != 0 || (*auth_pw & SSH_AUTH_KEYBOARD) != 0);
        if (onFailure == AuthFailureUi::StatusOnly || hasFallbackAuth) {
            ShowStatus(uiMsg.c_str());
        } else {
            ShowError(uiMsg.c_str());
        }
        AUTH_LOG("SftpAuthPubKey returning -IDS_ERR_AUTH_PUBKEY");
        clearPassphrase();
        return -IDS_ERR_AUTH_PUBKEY;
    }
    cleanupConvertedIfNeeded();
    // The key opened with this passphrase, so keep it whatever was there
    // before — a guess drawn from an unlabelled password field would
    // otherwise be re-tried, and fail, on every reconnect.
    if (auth == 0 && isencrypted && passphrase[0])
        *target.keyPassphrase = passphrase.data();
    clearPassphrase();
    AUTH_LOG("SftpAuthPubKey returning 0 (SUCCESS)");
    return 0;
}

// Bind the public-key flow to the target server. A failure here is a dead
// end for key auth, so it may raise a dialog — unlike a jump host, which
// still has password and keyboard-interactive left to try.
int SftpAuthPubKey(pConnectSettings ConnectSettings, LPCSTR progressbuf, int progress, int * ploop, SYSTICKS * plasttime, int * auth_pw,
                   bool* keyOpened)
{
    SshAuthTarget target;
    target.keyOpened   = keyOpened;
    target.session     = ConnectSettings->session.get();
    target.host        = ConnectSettings->server;
    target.user        = ConnectSettings->user;
    target.password    = &ConnectSettings->account_password;
    target.keyPassphrase = &ConnectSettings->key_passphrase;
    target.pubkeyfile  = ConnectSettings->pubkeyfile;
    target.privkeyfile = ConnectSettings->privkeyfile;
    target.waitIo      = [ConnectSettings]() { WaitForSshIo(ConnectSettings); };
    return SftpAuthPubKeyOn(target, progressbuf, progress, ploop, plasttime,
                            auth_pw, AuthFailureUi::Modal);
}
