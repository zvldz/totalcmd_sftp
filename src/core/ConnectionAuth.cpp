#include "global.h"
#include <windows.h>
#include <array>
#include <string>
#include <format>
#include "SftpClient.h"
#include "PluginEntryPoints.h"
#include "SftpInternal.h"
#include "ProxyNegotiator.h"
#include "IUserFeedback.h"
#include "AuthMethodParser.h"
#include "ConnectionAuth.h"
#include "ConnectionDialog.h"
#include "IniFile.h"
#include "res/resource.h"
#include "UnicodeHelpers.h"

// A server-mandated password change replaces the login password of the
// session and of the profile. A stored secret that also names the key's
// passphrase keeps it.
static void ApplyChangedPassword(pConnectSettings cs, const std::string& newpass)
{
    const StoredSecret old = SplitStoredSecret(cs->password);
    std::string stored = newpass;
    if (old.labelled)
        stored = "\"" + stored + "\",\"" + old.keyPassphrase + "\"";
    cs->password         = stored;
    cs->account_password = newpass;
    // Saved the way the profile keeps its password, with the dialog's
    // rules: a refusing store is reported, a failed encryption keeps the
    // old value, a stale store entry goes.
    if (cs->passSaveMode != sftp::PassSaveMode::empty)
        SavePasswordSetting(nullptr, cs->DisplayName.c_str(), "password",
                            cs->DisplayName.c_str(), stored,
                            cs->passSaveMode == sftp::PassSaveMode::crypt,
                            cs->IniFileName.c_str());
    SFTP_LOG("AUTH", "Changed password applied (saved=%d)",
             cs->passSaveMode != sftp::PassSaveMode::empty ? 1 : 0);
    SecureZeroMemory(stored.data(), stored.size());
}

extern "C"
void newpassfunc(LIBSSH2_SESSION* /*session*/, LPSTR* newpw, int* newpw_len, LPVOID* abstract)
{
    pConnectSettings PassConnectSettings = static_cast<pConnectSettings>(*abstract);
    std::array<char, 128> title{};
    std::array<char, 128> buf1{};
    std::array<char, 128> newpass{};
    LoadStr(title, IDS_PASS_TITLE);
    LoadStr(buf1, IDS_PASS_CHANGE_REQUEST);
    newpass[0] = 0;
    if (!newpw || !newpw_len)
        return;
    *newpw = nullptr;
    *newpw_len = 0;
    const bool answered = RequestProcI(PluginNumber, RT_Password, title.data(), buf1.data(),
                                       newpass.data(), newpass.size()-1) != 0;
    if (PassConnectSettings)
        PassConnectSettings->authPromptDone = get_sys_ticks();
    if (answered) {
        size_t bufsize = strlen(newpass.data()) + 1;
        *newpw = static_cast<char*>(malloc(bufsize));
        if (!*newpw)
            return;
        strlcpy(*newpw, newpass.data(), bufsize);
        *newpw_len = (int)strlen(newpass.data());
        if (PassConnectSettings) {
            std::string changed = newpass.data();
            ApplyChangedPassword(PassConnectSettings, changed);
            SecureZeroMemory(changed.data(), changed.size());
        }
    }
    SecureZeroMemory(newpass.data(), newpass.size());
}

// A password typed at a keyboard-interactive prompt becomes the session's
// password only when that login succeeded; a rejected one is dropped, so the
// password method that may follow asks again instead of sending it. A new
// password the server asked for replaces the old one, in the profile too.
static void CommitTypedPassword(pConnectSettings cs, bool loggedIn)
{
    if (loggedIn && !cs->changed_password.empty()) {
        ApplyChangedPassword(cs, cs->changed_password);
    } else if (loggedIn && !cs->typed_password.empty() && cs->account_password.empty()) {
        cs->account_password = cs->typed_password;
        if (cs->password.empty())
            cs->password = cs->typed_password;
    }
    SecureZeroMemory(cs->typed_password.data(), cs->typed_password.size());
    cs->typed_password.clear();
    SecureZeroMemory(cs->changed_password.data(), cs->changed_password.size());
    cs->changed_password.clear();
}

int NegotiateProxy(
    pConnectSettings ConnectSettings,
    unsigned short connecttoport,
    int& progress,
    int& loop,
    SYSTICKS& lasttime)
{
    if (ConnectSettings->proxytype == sftp::Proxy::notused)
        return 0;

    progress = 20; // PROG_SOCKET_CONNECT
    std::array<char, 250> progressbuf{};
    LoadStr(progressbuf, IDS_PROXY_CONNECT);
    if (ProgressProcI(PluginNumber, progressbuf.data(), "-", progress))
        return -40;

    int hr = 0;
    switch (ConnectSettings->proxytype) {
    case sftp::Proxy::http:
        hr = SftpConnectProxyHttp(ConnectSettings, progressbuf.data(), progress, &loop, &lasttime);
        if (hr) return -12040 - hr;
        break;
    case sftp::Proxy::socks4:
        hr = SftpConnectProxySocks4(ConnectSettings, progressbuf.data(), progress, &loop, &lasttime);
        if (hr) return -13040 - hr;
        break;
    case sftp::Proxy::socks5:
        hr = SftpConnectProxySocks5(ConnectSettings, connecttoport, progressbuf.data(), progress, &loop, &lasttime);
        if (hr) return -14040 - hr;
        break;
    default:
        break;
    }
    return 0;
}

int PerformAuthentication(
    pConnectSettings ConnectSettings,
    int& progress,
    int& loop,
    SYSTICKS& lasttime,
    char* progressbuf)
{
    std::array<char, 1024> buf{};
    char* userauthlist = nullptr;
    int auth_pw = 0;

    // Split the stored secret once, here, before any method runs. Everything
    // downstream reads account_password or key_passphrase by name. A
    // passphrase already remembered from an earlier attempt on this
    // connection survives, so reconnects do not prompt again.
    // An unlabelled secret is only a guess at either; a value already held —
    // entered at a prompt in an earlier attempt, or carried over from the
    // panel's connection — outranks it.
    const StoredSecret secret = SplitStoredSecret(ConnectSettings->password);
    if (secret.labelled) {
        if (!secret.accountPassword.empty())
            ConnectSettings->account_password = secret.accountPassword;
        if (!secret.keyPassphrase.empty())
            ConnectSettings->key_passphrase = secret.keyPassphrase;
    } else {
        if (ConnectSettings->account_password.empty())
            ConnectSettings->account_password = secret.accountPassword;
        if (ConnectSettings->key_passphrase.empty())
            ConnectSettings->key_passphrase = secret.keyPassphrase;
    }

    // A private key entered in the public-key field is still the key to log
    // in with; left there it is ignored, and a key-only server then ends the
    // login without a word. The swap is for this connection only.
    if (ConnectSettings->privkeyfile.empty() &&
        KeyFileHoldsPrivateKey(ConnectSettings->pubkeyfile, ConnectSettings->user)) {
        SFTP_LOG("AUTH", "Private key found in the public-key field: %s",
                 ConnectSettings->pubkeyfile.c_str());
        ShowStatus("Using the private key entered as the public key file");
        ConnectSettings->privkeyfile = ConnectSettings->pubkeyfile;
        ConnectSettings->pubkeyfile.clear();
    }

    // The probe is skipped only when there are credentials to try anyway.
    // With nothing configured it runs — shell-only mode included — so a
    // server that takes keys only is recognised instead of being asked for
    // a password it will refuse. A slow answer costs at most the probe's
    // own timeout, after which every method is assumed.
    const bool skipProbe = !ConnectSettings->password.empty()
        || !ConnectSettings->privkeyfile.empty();
    if (skipProbe) {
        ShowStatusId(IDS_LOG_SCP_SKIP_PROBE, nullptr, true);
        // Skip userauthList probe when credentials are known: avoids hanging on
        // servers (e.g. OVH) that respond slowly to the "none" auth request.
        auth_pw = SSH_AUTH_PASSWORD | SSH_AUTH_KEYBOARD | SSH_AUTH_PUBKEY;
    } else {
        SYSTICKS authListStart = get_sys_ticks();
        do {
            userauthlist = ConnectSettings->session->userauthList(ConnectSettings->user.c_str(), (UINT)ConnectSettings->user.size());
            LoadStr(buf, IDS_USER_AUTH_LIST);
            if (ProgressLoop(buf.data(), progress, progress + 10, &loop, &lasttime))
                break;
            if (get_ticks_between(authListStart) > SSH_PROBE_TIMEOUT_MS) {
                ShowStatusId(IDS_LOG_AUTH_METHODS_TIMEOUT, nullptr, true);
                break;
            }
            if (!userauthlist && ConnectSettings->session->lastErrno() == LIBSSH2_ERROR_EAGAIN)
                WaitForTransportReadable(ConnectSettings);
        } while (userauthlist == nullptr && ConnectSettings->session->lastErrno() == LIBSSH2_ERROR_EAGAIN);

        const std::string uaLog = std::format("userauthlist='{}' errno={}",
            userauthlist ? userauthlist : "(null)", ConnectSettings->session->lastErrno());
        ShowStatus(uaLog.c_str());

        if (userauthlist) {
            ShowStatusId(IDS_SUPPORTED_AUTH_METHODS, userauthlist, true);
            auth_pw = ParseAuthMethodsFromUserauthList(userauthlist);
            if (auth_pw == 0) {
                ShowStatusId(IDS_LOG_AUTH_METHODS_NONE, nullptr, true);
                // Some servers return malformed method lists; keep a compatibility path.
                auth_pw = SSH_AUTH_PASSWORD | SSH_AUTH_KEYBOARD | SSH_AUTH_PUBKEY;
            }
        } else {
            SftpLogLastError("libssh2_userauth_list: ", ConnectSettings->session->lastErrno());
            // NULL list after timeout/EAGAIN is treated as non-fatal for compatibility.
            auth_pw = SSH_AUTH_PASSWORD | SSH_AUTH_KEYBOARD | SSH_AUTH_PUBKEY;
        }
    }

    int auth = 0;
    if (ConnectSettings->session->userauthAuthenticated()) {
        ShowStatusId(IDS_LOG_AUTH_NO_PASSWORD, nullptr, true);
    } else if ((auth_pw & SSH_AUTH_PUBKEY) &&
               (ConnectSettings->useagent || ConnectSettings->privkeyfile[0])) {
        // Pageant first, then the key file: a key the agent does not hold is
        // still tried from its file.
        progress = 65;
        if (ConnectSettings->useagent) {
            int rc = SftpAuthPageant(ConnectSettings, progressbuf, progress, &loop, &lasttime, &auth_pw);
            auth = (rc < 0) ? LIBSSH2_ERROR_AGENT_PROTOCOL : 0;
            const std::string status = std::format("Pageant: rc={} auth={}", rc, auth);
            ShowStatus(status.c_str());
        }
        if ((!ConnectSettings->useagent || auth != 0) && ConnectSettings->privkeyfile[0]) {
            LogProcI(PluginNumber, MSGTYPE_DETAILS, "=== Calling SftpAuthPubKey ===");
            bool keyOpened = false;
            int rc = SftpAuthPubKey(ConnectSettings, progressbuf, progress, &loop, &lasttime, &auth_pw,
                                    &keyOpened);
            auth = (rc < 0) ? LIBSSH2_ERROR_FILE : 0;
            // The unlabelled secret opened the key, so it is the key's
            // passphrase: offered to the server as the password it would be
            // disclosed. The password is asked for instead.
            if (rc < 0 && keyOpened && !secret.labelled && !secret.accountPassword.empty() &&
                ConnectSettings->key_passphrase == secret.accountPassword &&
                ConnectSettings->account_password == secret.accountPassword) {
                SFTP_LOG("AUTH", "Stored secret opened the key: not offered as the password");
                ConnectSettings->account_password.clear();
            }
            if (rc == -LIBSSH2_ERROR_FILE) {
                SFTP_LOG("CONN", "Public-key auth aborted due to local key file error.");
                return SFTP_FAILED;
            }
            LogProcI(PluginNumber, MSGTYPE_DETAILS, "=== SftpAuthPubKey returned ===");
            const std::string status = std::format("PubKey: rc={} auth={} pw=0x{:x}", rc, auth, auth_pw);
            ShowStatus(status.c_str());
        }
    } else {
        // A server that takes keys only, with neither a key file nor a
        // running Pageant to offer it, leaves nothing to try; say so rather
        // than let the login end without a word.
        if (auth_pw == SSH_AUTH_PUBKEY) {
            SFTP_LOG("AUTH", "Server accepts only public keys; none to offer");
            ShowErrorId(IDS_ERR_KEY_ONLY_NO_KEY);
        }
        auth_pw &= ~SSH_AUTH_PUBKEY;
    }

    LogProcI(PluginNumber, MSGTYPE_DETAILS, "=== Auth section done ===");
    progress = 70; // PROG_AUTH_DONE
    if (auth != 0 || (auth_pw & SSH_AUTH_PUBKEY) == 0) {
        LogProcI(PluginNumber, MSGTYPE_DETAILS, "Trying password/keyboard auth fallback");
        const bool canKeyboardAuth = (auth_pw & SSH_AUTH_KEYBOARD) != 0;
        const bool canPasswordAuth = (auth_pw & SSH_AUTH_PASSWORD) != 0;
        // If the probe was done and confirmed password auth, try it first to avoid
        // consuming keyboard-interactive attempts on OTP/MFA prompts.
        // When probe was skipped we don't know the server's supported methods,
        // so keyboard-interactive goes first; kbd_callback will auto-send the
        // stored password for password-like prompts (e.g. OVH).
        const bool preferPasswordFirst = !skipProbe && canPasswordAuth && !ConnectSettings->account_password.empty();
        bool skippedKeyboardFirst = false;

        if (canKeyboardAuth && !preferPasswordFirst) {
            ShowStatusId(IDS_AUTH_KEYBDINT_FOR, ConnectSettings->user.c_str(), true);
            LoadStr(buf, IDS_AUTH_KEYBDINT);
            pConnectSettings cs = ConnectSettings;
            cs->InteractivePasswordSent = false;
            const SYSTICKS authStart = get_sys_ticks();
            int kbdIter = 0;
            while ((auth = cs->session->userauthKeyboardInteractive(cs->user.c_str(), (unsigned)cs->user.size(), &kbd_callback)) == LIBSSH2_ERROR_EAGAIN) {
                const int dirs = cs->session->blockDirections();
                const DWORD elapsed = (DWORD)get_ticks_between((std::max)(authStart, cs->authPromptDone));
                SFTP_LOG("AUTH", "kbd EAGAIN #%d dirs=0x%x elapsed=%u cbSent=%d", ++kbdIter, dirs, elapsed, cs->InteractivePasswordSent ? 1 : 0);
                if (ProgressLoop(buf.data(), progress, progress + 10, &loop, &lasttime))
                    break;
                if (elapsed > SSH_AUTH_STAGE_TIMEOUT_MS) {
                    ShowStatusId(IDS_LOG_KBD_AUTH_TIMEOUT, nullptr, true);
                    break;
                }
                WaitForSshIo(cs);
            }
            SFTP_LOG("AUTH", "kbd done auth=%d iters=%d cbSent=%d", auth, kbdIter, ConnectSettings->InteractivePasswordSent ? 1 : 0);
            CommitTypedPassword(ConnectSettings, auth == 0);
            if (auth) {
                SftpLogLastError("libssh2_userauth_keyboard_interactive: ", auth);
                if ((auth_pw & SSH_AUTH_PASSWORD) == 0)
                    ShowErrorId(IDS_ERR_AUTH_KEYBDINT);
            }
        } else {
            auth = LIBSSH2_ERROR_INVAL;
            skippedKeyboardFirst = canKeyboardAuth;
        }
        // The stored password keyboard-interactive already sent and the
        // server refused: sending it again only counts towards a lockout.
        bool storedRefused = auth != 0 && !skippedKeyboardFirst && canKeyboardAuth &&
                             ConnectSettings->InteractivePasswordSent;
        bool cancelled = false;   // Cancel at a password prompt ends the login
        if (auth != 0 && canPasswordAuth) {
            std::string passphrase = storedRefused ? std::string() : ConnectSettings->account_password;
            bool typed = false;
            // The stored password is sent once; a refused one, or none, is
            // asked for, up to three times. Cancel ends it, and so does any
            // answer but "refused": an expired password, a dropped link.
            for (int typedTries = 0; ; ) {
                if (passphrase.empty()) {
                    if (typedTries == 3)
                        break;
                    ++typedTries;
                    std::string title = std::format("SFTP password for {}@{}", ConnectSettings->user, ConnectSettings->server);
                    bool answered;
                    if (ConnectSettings->feedback) {
                        answered = ConnectSettings->feedback->RequestText(title, "", passphrase, true);
                    } else {
                        std::array<char, 256> tmpBuf{};
                        answered = RequestProcI(PluginNumber, RT_Password, title.c_str(), nullptr, tmpBuf.data(), tmpBuf.size()-1) != 0;
                        passphrase = tmpBuf.data();
                        SecureZeroMemory(tmpBuf.data(), tmpBuf.size());
                    }
                    ConnectSettings->authPromptDone = get_sys_ticks();
                    SFTP_LOG("AUTH", "Password asked (try %d): answered=%d", typedTries, answered ? 1 : 0);
                    if (!answered) {
                        auth = LIBSSH2_ERROR_AUTHENTICATION_FAILED;
                        cancelled = true;
                        break;
                    }
                    typed = true;
                }

                ShowStatusId(IDS_AUTH_PASSWORD_FOR, ConnectSettings->user.c_str(), true);
                LoadStr(buf, IDS_AUTH_PASSWORD);
                const SYSTICKS authStart = get_sys_ticks();
                int passIter = 0;
                // PASSWORD_EXPIRED is final: the server wanted a new password and
                // none was given. Calling again would re-enter libssh2 with the
                // state of the change it already gave up.
                while (1) {
                    auth = ConnectSettings->session->userauthPassword(ConnectSettings->user.c_str(), (unsigned)ConnectSettings->user.size(), passphrase.c_str(), (unsigned)passphrase.length(), &newpassfunc);
                    if (auth != LIBSSH2_ERROR_EAGAIN)
                        break;
                    {
                        const int dirs = ConnectSettings->session->blockDirections();
                        const DWORD elapsed = (DWORD)get_ticks_between((std::max)(authStart, ConnectSettings->authPromptDone));
                        SFTP_LOG("AUTH", "pass EAGAIN #%d dirs=0x%x elapsed=%u", ++passIter, dirs, elapsed);
                        if (ProgressLoop(buf.data(), progress, progress + 10, &loop, &lasttime))
                            break;
                        if (elapsed > SSH_AUTH_STAGE_TIMEOUT_MS) {
                            ShowStatusId(IDS_LOG_PASS_AUTH_TIMEOUT, nullptr, true);
                            break;
                        }
                        WaitForSshIo(ConnectSettings);
                    }
                }
                SFTP_LOG("AUTH", "pass done auth=%d iters=%d typed=%d", auth, passIter, typed ? 1 : 0);
                if (auth != LIBSSH2_ERROR_AUTHENTICATION_FAILED)
                    break;
                if (!typed)
                    storedRefused = true;
                ShowStatusId(IDS_ERR_AUTH_PASSWORD, nullptr, true);
                SecureZeroMemory(passphrase.data(), passphrase.size());
                passphrase.clear();
                typed = false;
            }
            if (auth) {
                SftpLogLastError("libssh2_userauth_password_ex: ", auth);
                // Cancel at the prompt is the user's own choice, not an error.
                if (!skippedKeyboardFirst && !cancelled)
                    ShowErrorId(IDS_ERR_AUTH_PASSWORD);
                else
                    ShowStatusId(IDS_ERR_AUTH_PASSWORD, nullptr, true);
            } else if (typed) {
                // Remember it for the reconnects that run mid-transfer, in
                // place of a stored one the server refused. The stored form
                // only takes it over when it holds nothing at all, so a
                // profile that packs a passphrase keeps it.
                ConnectSettings->account_password = passphrase;
                if (ConnectSettings->password.empty())
                    ConnectSettings->password = passphrase;
            }
            SecureZeroMemory(passphrase.data(), passphrase.size());
        }

        if (auth != 0 && skippedKeyboardFirst && !cancelled) {
            // Retry keyboard-interactive after password failure for servers that expose
            // both methods but only accept one depending on account policy.
            ShowStatusId(IDS_AUTH_KEYBDINT_FOR, ConnectSettings->user.c_str(), true);
            LoadStr(buf, IDS_AUTH_KEYBDINT);
            pConnectSettings cs = ConnectSettings;
            // A stored password the password method had refused is not
            // offered again: every prompt goes to the user.
            cs->InteractivePasswordSent = storedRefused;
            const SYSTICKS authStart = get_sys_ticks();
            int kbdIter2 = 0;
            while ((auth = cs->session->userauthKeyboardInteractive(cs->user.c_str(), (unsigned)cs->user.size(), &kbd_callback)) == LIBSSH2_ERROR_EAGAIN) {
                const int dirs = cs->session->blockDirections();
                const DWORD elapsed = (DWORD)get_ticks_between((std::max)(authStart, cs->authPromptDone));
                SFTP_LOG("AUTH", "kbd2 EAGAIN #%d dirs=0x%x elapsed=%u cbSent=%d", ++kbdIter2, dirs, elapsed, cs->InteractivePasswordSent ? 1 : 0);
                if (ProgressLoop(buf.data(), progress, progress + 10, &loop, &lasttime))
                    break;
                if (elapsed > SSH_AUTH_STAGE_TIMEOUT_MS) {
                    ShowStatusId(IDS_LOG_KBD_AUTH_TIMEOUT, nullptr, true);
                    break;
                }
                WaitForSshIo(cs);
            }
            SFTP_LOG("AUTH", "kbd2 done auth=%d iters=%d cbSent=%d", auth, kbdIter2, ConnectSettings->InteractivePasswordSent ? 1 : 0);
            CommitTypedPassword(ConnectSettings, auth == 0);
            if (auth) {
                SftpLogLastError("libssh2_userauth_keyboard_interactive: ", auth);
                ShowErrorId(IDS_ERR_AUTH_KEYBDINT);
            }
        }
    }

    const std::string authLog = std::format("Auth complete: auth={} auth_pw=0x{:x} scponly={}", auth, auth_pw, ConnectSettings->scponly);
    ShowStatus(authLog.c_str());
    SFTP_LOG("CONN", "%s", authLog.c_str());

    if (auth) {
        if (LogProc || LogProcW) {
            const std::string msg = std::format("SFTP: Authentication failed for '{}@{}'",
                ConnectSettings->user, ConnectSettings->server);
            LogProcI(PluginNumber, MSGTYPE_IMPORTANTERROR, msg.c_str());
        }
        SFTP_LOG("CONN", "Auth failed, returning SFTP_FAILED");
        return SFTP_FAILED;
    }
    return 0;
}
