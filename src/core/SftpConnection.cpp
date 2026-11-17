// SFTP transport/session implementation.
#include "global.h"
#include <windows.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <shellapi.h>
#include <commdlg.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <stdio.h>
#include <fcntl.h>
#include "SftpClient.h"
#include "PluginEntryPoints.h"
#include "fsplugin.h"
#include "ServerRegistry.h"
#include "res/resource.h"
#include "CoreUtils.h"
#include "UnicodeHelpers.h"

#include "SftpInternal.h"
#include "Utf8Escape.h"
#include "SshBackendFactory.h"
#include "WindowsUserFeedback.h"
#include <algorithm>
#include <array>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <new>
#include <fstream>
#include <iterator>
#include <vector>
#if SFTP_EXTRA
#include "PhpAgentClient.h"
#endif
#include "ConnectionDialog.h"
#include "SessionPostAuth.h"
#include "ConnectionLifecycle.h"
#include "ConnectionNetwork.h"
#include "SshSessionInit.h"
#include "PluginEntryPointsInternal.h"
#include "ConnectionAuth.h"
#if SFTP_EXTRA
#include "LanPairSession.h"
#endif
#include "JumpHostConnection.h"
#include "IniFile.h"

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "bcrypt.lib")

#define CONN_LOG(fmt, ...) SFTP_LOG("CONN", fmt, ##__VA_ARGS__)

// Global SSH backend instance (created once, never changes)
static std::unique_ptr<ISshBackend> g_sshBackend;
static std::once_flag g_sshBackendOnce;

// Creates the backend and initialises libssh2 exactly once, whichever
// thread connects first: libssh2's implicit initialisation inside the
// first session is not thread-safe.
static void EnsureSshBackend()
{
    std::call_once(g_sshBackendOnce, [] {
        libssh2_init(0);
        g_sshBackend = CreateSshBackend();
    });
}

// Global LAN Pair file server: started when a LAN Pair session is opened,
// serves all authenticated peers. Also the discovery service that
// announces this machine's presence.
#if SFTP_EXTRA
static std::unique_ptr<LanFileServer>    g_lanFileServer;
static std::unique_ptr<lanpair::DiscoveryService> g_lanDiscovery;
#endif

// ---------------------------------------------------------------------------
// Connection progress step percentages
// ---------------------------------------------------------------------------
static constexpr int PROG_SOCKET_CONNECT  = 20;
static constexpr int PROG_AUTH_START      = 60;
static constexpr int PROG_SFTP_INIT       = 80;
static constexpr int PROG_DONE            = 90;

bool serverfieldchangedbyuser = false;
char Global_TransferMode = 'I';  //I=Binary,  A=Ansi,  X=Auto
std::array<WCHAR, 1024> Global_TextTypes{};
std::mutex g_transferModeMutex;

thread_local char global_detectcrlf = 0;

const bool SSH_ScpNo2GBLimit = true;

void EncryptString(LPCTSTR pszPlain, LPTSTR pszEncrypted, UINT cchEncrypted);


bool EscapePressed() noexcept
{
    // Honor Escape only for the current process.
    if (GetAsyncKeyState(VK_ESCAPE) < 0) {
        DWORD procid1 = 0;
        HWND hwnd = GetActiveWindow();
        if (hwnd) {
            GetWindowThreadProcessId(hwnd, &procid1);
            if (procid1 == GetCurrentProcessId())
                return true;
        }
    }
    return false;
}

void wcslcpytoutf8(LPSTR utf8str, LPCWSTR utf16str, size_t maxlen)
{
    ConvUTF16toUTF8(utf16str, 0, utf8str, maxlen);
}

// A path cut to fit would name a different file, so a string that does not
// fit (terminator included, one slot kept free) is not converted at all and
// comes out empty.
static bool FitsW2A(int codepage, LPCWSTR s, size_t outmax) noexcept
{
    const int needed = WideCharToMultiByte(codepage, 0, s, -1, nullptr, 0, nullptr, nullptr);
    return needed > 0 && static_cast<size_t>(needed) < outmax;
}

static bool FitsA2W(int codepage, LPCSTR s, size_t outmax) noexcept
{
    const int needed = MultiByteToWideChar(codepage, 0, s, -1, nullptr, 0);
    return needed > 0 && static_cast<size_t>(needed) < outmax;
}

// A name the session's codepage cannot hold is not converted either. Windows
// would otherwise pick a look-alike or '?': two names collapsing into one, or
// a fullwidth apostrophe arriving as a quote inside a shell command.
bool CopyStringW2A(pConnectSettings ConnectSettings, LPCWSTR instr, LPSTR outstr, size_t outmax) noexcept
{
    if (!outstr || outmax == 0)
        return false;
    outstr[0] = '\0';
    if (!instr)
        return false;
    // UTF-8: bytes a name held that were not UTF-8 go back as they came
    // (utf8_escape).
    if (ConnectSettings->utf8names > 0) {
        try {
            const std::string bytes = utf8_escape::Encode(instr);
            if (bytes.size() >= outmax)
                return false;
            memcpy(outstr, bytes.c_str(), bytes.size() + 1);
            return true;
        } catch (...) {
            return false;
        }
    }
    const int codepage = ConnectSettings->codepage;
    if (!FitsW2A(codepage, instr, outmax))
        return false;
    BOOL usedDefault = FALSE;
    const int n = WideCharToMultiByte(codepage, WC_NO_BEST_FIT_CHARS, instr, -1, outstr,
                                      static_cast<int>(outmax), nullptr, &usedDefault);
    if (n <= 0 || usedDefault) {
        outstr[0] = '\0';
        return false;
    }
    return true;
}

bool CopyRemotePathW2A(pConnectSettings ConnectSettings, LPCWSTR path, LPSTR outstr, size_t outmax) noexcept
{
    if (!outstr || outmax == 0)
        return false;
    outstr[0] = '\0';
    if (!path)
        return false;
    try {
        std::wstring slashed(path);
        std::replace(slashed.begin(), slashed.end(), L'\\', L'/');
        return CopyStringW2A(ConnectSettings, slashed.c_str(), outstr, outmax);
    } catch (...) {
        return false;
    }
}

void CopyStringA2W(pConnectSettings ConnectSettings, LPCSTR instr, LPWSTR outstr, size_t outmax,
                   [[maybe_unused]] bool useCVT) noexcept
{
    if (!outstr || outmax == 0)
        return;
    outstr[0] = L'\0';
    if (!instr)
        return;
    // UTF-8: a byte that is not part of valid UTF-8 is kept, as a stand-in
    // CopyStringW2A turns back into it, rather than lost to U+FFFD.
    if (ConnectSettings->utf8names > 0) {
        try {
            const std::wstring text = utf8_escape::Decode(instr);
            if (text.size() < outmax)
                memcpy(outstr, text.c_str(), (text.size() + 1) * sizeof(wchar_t));
        } catch (...) {
        }
        return;
    }
    if (!FitsA2W(ConnectSettings->codepage, instr, outmax))
        return;
    awlcopyCP(ConnectSettings->codepage, outstr, instr, outmax - 1);
}

bool ProgressLoop(LPCSTR progresstext, int start, int end, int * loopval, SYSTICKS * lasttime)
{
    SYSTICKS time = get_sys_ticks();
    if (time - *lasttime > PROGRESS_UPDATE_MS || *loopval < start) {
        *lasttime = time;
        (*loopval)++;
        if (*loopval < start || *loopval > end)
            *loopval = start;
        return ProgressProcI(PluginNumber, progresstext, "-", *loopval) != 0;    // "-" = no target file (TC plugin API convention)
    }
    return false;
}

void SftpLogLastError(LPCSTR errtext, int errnr)
{
    std::array<char, 128> errbuf{};
    if (errnr == 0 || errnr == LIBSSH2_ERROR_EAGAIN)   //no error -> do not log
        return;
    
    // Formatting: "text: error_number"
    snprintf(errbuf.data(), errbuf.size(), "%s %d", errtext ? errtext : "libssh2", errnr);
    LogProcI(PluginNumber, MSGTYPE_IMPORTANTERROR, errbuf.data());
}

void ShowMessageIdEx(int errorid, LPCSTR p1, int p2, bool silent)
{
    if (errorid < 0)
        return;
    std::array<char, 256> loadedStr{};
    LoadStr(loadedStr, errorid);
    std::string msg = loadedStr.data();
    if (p1) {
        auto pos = msg.find("%s");
        if (pos != std::string::npos)
            msg.replace(pos, 2, p1);
        else if ((pos = msg.find("%d")) != std::string::npos)
            msg.replace(pos, 2, std::to_string(p2));
        else
            msg += p1;
    }
    ShowStatus(msg.c_str());  // log it
    if (!silent)
        RequestProcI(PluginNumber, RT_MsgOK, "SFTP Error", msg.c_str(), nullptr, 0);
}

void ShowStatusId(int errorid, bool silent, int value)
{
    ShowMessageIdEx(errorid, "", value, silent);
}

void ShowStatusId(int errorid, LPCSTR suffix, bool silent)
{
    ShowMessageIdEx(errorid, suffix, 0, silent);
}

void ShowErrorId(int errorid, LPCSTR suffix)
{
    ShowMessageIdEx(errorid, suffix, 0, false);
}

void ShowError(LPCSTR error)
{
    ShowStatus(error);  // log it
    RequestProcI(PluginNumber, RT_MsgOK, "SFTP Error", error, nullptr, 0);
}


void SetBlockingSocket(SOCKET s, bool blocking)
{
    u_long arg = blocking ? 0 : 1;
    ioctlsocket(s, FIONBIO, &arg);
}

// Keeps NAT and firewall mappings alive while a session sits idle: the
// kernel probes after 60 s of silence and every 10 s after that, with no
// SSH traffic and no thread of our own. A dead peer is noticed too.
void EnableTcpKeepAlive(SOCKET s)
{
    tcp_keepalive ka{1, 60000, 10000};
    DWORD bytes = 0;
    WSAIoctl(s, SIO_KEEPALIVE_VALS, &ka, sizeof(ka), nullptr, 0, &bytes, nullptr, nullptr);
}

bool IsSocketError(SOCKET s)
{
    fd_set fds;
    timeval timeout = gettimeval(SOCKET_POLL_MS);
    FD_ZERO(&fds);
    FD_SET(s, &fds);
    return 1 == select(0, nullptr, nullptr, &fds, &timeout);
}

// True if the raw TCP endpoint has been closed by the peer (server reboot,
// firewall reset, or half-closed FIN). Non-destructive: uses select+recv
// with MSG_PEEK so any bytes in the receive buffer stay there for the next
// legitimate read by libssh2.
static bool IsTcpSocketDead(SOCKET s) noexcept
{
    if (s == INVALID_SOCKET) return true;

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(s, &rfds);
    struct timeval tv = { 0, 0 };  // instant, no wait
    const int selRet = select(0, &rfds, nullptr, nullptr, &tv);
    if (selRet < 0)                  return true;   // select failed → treat as dead
    if (selRet == 0)                 return false;  // no data pending, idle-but-alive

    // Socket is readable — could be legit incoming data OR a FIN/RST. Peek
    // one byte non-destructively. recv == 0 is the WinSock signal for a
    // gracefully closed peer; a real error other than WOULDBLOCK is a hard
    // dead connection.
    char peek = 0;
    const int rc = recv(s, &peek, 1, MSG_PEEK);
    if (rc == 0)                     return true;
    if (rc < 0) {
        const int err = WSAGetLastError();
        return err != WSAEWOULDBLOCK;
    }
    return false;  // real data present → alive
}

bool IsSessionAlive(pConnectSettings cs) noexcept
{
    if (!cs) return false;

    // LAN Pair carries its own connected-state accessor; the classic build
    // never connects one.
    if (IsLanPairTransport(cs)) {
#if SFTP_EXTRA
        return cs->lanSession && cs->lanSession->isConnected();
#else
        return false;
#endif
    }

    // PHP Agent uses HTTP-over-transport; no long-lived TCP to probe. If
    // the client object exists we optimistically consider it alive — the
    // next request will error normally and drive a reconnect through the
    // agent's own retry path.
    if (IsPhpAgentTransport(cs))
        return true;

    // Regular SSH / SCP path.
    if (!cs->session)                return false;
    if (cs->sock == INVALID_SOCKET)  return false;
    if (IsTcpSocketDead(cs->sock))   return false;
    return true;
}

bool IsSocketWritable(SOCKET s)
{
    fd_set fds;
    timeval timeout = gettimeval(SOCKET_POLL_MS);
    FD_ZERO(&fds);
    FD_SET(s, &fds);
    return 1 == select(0, nullptr, &fds, nullptr, &timeout);
}

bool IsSocketReadable(SOCKET s)
{
    fd_set fds;
    // Wingate local requires a non-zero timeout in select().
    timeval timeout = gettimeval(SOCKET_READ_POLL_MS);
    FD_ZERO(&fds);
    FD_SET(s, &fds);
    int err = select(0, &fds, nullptr, nullptr, &timeout);
    return (err == 1);
}

bool WaitForTransportReadable(pConnectSettings cs)
{
    if (!cs)
        return false;
    if (cs->transport_stream)
        return cs->transport_stream->waitReadable(SOCKET_READ_POLL_MS);
    return IsSocketReadable(cs->sock);
}

// Block_directions-aware wait. Picks read/write/both based on what libssh2
// says it's waiting on; falls back to read when libssh2 has no opinion.
// For ProxyJump the transport stream handles the nested wait — inner
// OUTBOUND can unblock via either incoming window-update (jump read) or
// outbound jump-TCP drain (jump write).
bool WaitForSshIo(pConnectSettings cs, DWORD timeoutMs)
{
    if (!cs)
        return false;

    if (cs->transport_stream)
        return cs->transport_stream->waitForSshIo(cs->session.get(), timeoutMs);

    if (cs->sock == INVALID_SOCKET)
        return false;

    const int dirs = cs->session ? cs->session->blockDirections() : 0;
    fd_set rfds, wfds;
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);

    if (dirs & LIBSSH2_SESSION_BLOCK_INBOUND)
        FD_SET(cs->sock, &rfds);
    if (dirs & LIBSSH2_SESSION_BLOCK_OUTBOUND)
        FD_SET(cs->sock, &wfds);
    if (!dirs)
        FD_SET(cs->sock, &rfds);

    timeval tv = { static_cast<long>(timeoutMs / 1000),
                   static_cast<long>((timeoutMs % 1000) * 1000) };
    return select(0, &rfds, &wfds, nullptr, &tv) > 0;
}

// Sends all `len` bytes; the count on success, SOCKET_ERROR on a socket error
// or when the user cancels.
extern "C"
int mysend(SOCKET s, LPCSTR buf, int len, int flags, LPCSTR progressmessage, int progressstart, int * ploop, SYSTICKS * plasttime)
{
    int sent = 0;
    while (sent < len) {
        const int ret = send(s, buf + sent, len - sent, flags);
        if (ret > 0) {
            sent += ret;
            continue;
        }
        if (ret == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK)
            return SOCKET_ERROR;
        if (ProgressLoop(progressmessage, progressstart, progressstart + 10, ploop, plasttime))
            return SOCKET_ERROR;
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(s, &wfds);
        timeval tv = { static_cast<long>(SOCKET_READ_POLL_MS / 1000),
                       static_cast<long>((SOCKET_READ_POLL_MS % 1000) * 1000) };
        select(0, nullptr, &wfds, nullptr, &tv);
    }
    return sent;
}

// Receives exactly `len` bytes; `len` on success. A peer that closes first
// (recv returns 0) is an error like any other, not a reason to wait on.
extern "C"
int myrecv(SOCKET s, LPSTR buf, int len, int flags, LPCSTR progressmessage, int progressstart, int * ploop, SYSTICKS * plasttime)
{
    int totallen = len;
    int ret = SOCKET_ERROR;
    while (true) {
        if (IsSocketReadable(s)) {
            ret = recv(s, buf, len, flags);
            if (ret == len)
                return totallen;
            if (ret > 0) {
                buf += ret;
                len -= ret;
                continue;
            }
            if (ret == 0)
                return SOCKET_ERROR;
            if (WSAGetLastError() != WSAEWOULDBLOCK)
                return ret;
        }
        if (ProgressLoop(progressmessage, progressstart, progressstart + 10, ploop, plasttime))
            break;   /* User aborted. */
        // No Sleep here: IsSocketReadable() above already blocked up to
        // SOCKET_READ_POLL_MS waiting for data; extra Sleep would just be
        // dead wait.
    }
    return ret;
}

// ---------------------------------------------------------------------------
// LAN Pair global server management (extra build only)
// ---------------------------------------------------------------------------
#if SFTP_EXTRA

// Generate a stable peer ID for this machine/process combination.
static std::string MakeLanPeerId()
{
    char host[256] = {};
    gethostname(host, static_cast<int>(sizeof(host) - 1));
    return std::string(host); // hostname only — stable across TC restarts
}

void StartGlobalLanServices(bool startServer)
{
    if (startServer && (!g_lanFileServer || !g_lanFileServer->isRunning())) {
        g_lanFileServer = std::make_unique<LanFileServer>();
        lanpair::PairError err;
        if (!g_lanFileServer->start(45846, &err)) {
            SFTP_LOG("LAN", "LanFileServer start failed: %s", err.message.c_str());
            g_lanFileServer.reset();
        } else {
            // Restore previously saved server password (set when any LAN Pair profile was connected).
            std::string storedPw;
            if (lanpair::DpapiSecretStore::loadSecret("lanpair-server-pw", &storedPw, nullptr) &&
                !storedPw.empty()) {
                g_lanFileServer->setPassword(storedPw);
            }
        }
    }

    if (!g_lanDiscovery) {
        g_lanDiscovery = std::make_unique<lanpair::DiscoveryService>();
        lanpair::DiscoveryConfig cfg;
        const std::string peerId = MakeLanPeerId();
        char host[256] = {};
        gethostname(host, static_cast<int>(sizeof(host) - 1));
        lanpair::PairError derr;
        if (!g_lanDiscovery->start(cfg, peerId, host, lanpair::PairRole::Dual,
                                   nullptr, &derr)) {
            SFTP_LOG("LAN", "LanDiscovery start failed: %s", derr.message.c_str());
            g_lanDiscovery.reset();
        }
    }
}

void LanFileServerSetPassword(const std::string& pw)
{
    if (g_lanFileServer)
        g_lanFileServer->setPassword(pw);
}

bool LanFileServerIsRunning()
{
    return g_lanFileServer && g_lanFileServer->isRunning();
}

void LanFileServerSetTrustedInstaller(bool enabled)
{
    if (g_lanFileServer)
        g_lanFileServer->setTrustedInstaller(enabled);
}

void StopGlobalLanServices()
{
    if (g_lanDiscovery) { g_lanDiscovery->stop(); g_lanDiscovery.reset(); }
    if (g_lanFileServer) { g_lanFileServer->stop(); g_lanFileServer.reset(); }
}

// Open LAN Pair client sessions, and whether this machine was opened as a
// Donor. The services run while a session is open; a Donor has no session
// of its own (the Receiver connects to it), so once opened it serves until
// Total Commander exits.
static std::atomic<int>  g_lanSessionCount{0};
static std::atomic<bool> g_lanDonorOpened{false};

static void StopLanServicesIfUnused()
{
    if (g_lanSessionCount.load() <= 0 && !g_lanDonorOpened.load()) {
        SFTP_LOG("LAN", "no LAN Pair session left: stopping file server and discovery");
        StopGlobalLanServices();
    }
}

// Drops a session's LAN Pair client and, with the last one gone, the services.
static void ReleaseLanSession(pConnectSettings cs)
{
    if (!cs->lanSession)
        return;
    cs->lanSession->disconnect();
    cs->lanSession.reset();
    --g_lanSessionCount;
    StopLanServicesIfUnused();
}

// Connect a LAN Pair session: run discovery to find the peer's current IP,
// then connect and run the PAIR3 handshake (password, or the stored key).
static int LanPairConnect(pConnectSettings cs)
{
    // lan_pair_role: 0=mutual, 1=receiver (biorca), 2=donor (dawca)
    if (cs->lan_pair_role == 2) {
        g_lanDonorOpened = true;
        StartGlobalLanServices(true);   // ensure our server is running for inbound connections
        if (cs->feedback)
            cs->feedback->ShowError(LngStrU8(IDS_LAN_ERR_DONOR_NO_CONNECT,
                "LAN Pair: this machine is configured as Donor. The remote Receiver must connect here.").c_str());
        return SFTP_FAILED;
    }
    // Receiver (role==1) does not start a local file server; mutual (role==0) starts both.
    StartGlobalLanServices(cs->lan_pair_role == 0);

    // If we already have an active session, nothing to do.
    if (cs->lanSession && cs->lanSession->isConnected())
        return SFTP_OK;
    if (cs->lanSession) {
        cs->lanSession.reset();
        --g_lanSessionCount;
    }
    // A connect that ends without a session leaves no reason for the
    // services this call started.
    const auto fail = [] {
        StopLanServicesIfUnused();
        return SFTP_FAILED;
    };

    ShowStatusId(IDS_LOG_LAN_DISCOVER, nullptr, true);

    // Wait up to 4 seconds for discovery to find the peer.
    const std::string targetPeerId = cs->lan_pair_peer;
    if (targetPeerId.empty()) {
        if (cs->feedback)
            cs->feedback->ShowError(LngStrU8(IDS_LAN_ERR_NO_PEER, "LAN Pair: no peer configured. Open connection settings and pair first.").c_str());
        return fail();
    }

    std::string foundIp;
    uint16_t foundPort = 45846;

    // Start a short-lived discovery service to look for the peer.
    lanpair::DiscoveryService disco;
    lanpair::DiscoveryConfig dcfg;
    const std::string localId = MakeLanPeerId();
    char host[256] = {};
    gethostname(host, static_cast<int>(sizeof(host) - 1));

    std::mutex mu;
    std::condition_variable cv;
    bool found = false;

    disco.start(dcfg, localId, host, lanpair::PairRole::Dual,
        [&](const lanpair::PeerAnnouncement& ann) {
            if (ann.peerId != targetPeerId) return;
            std::lock_guard<std::mutex> lk(mu);
            foundIp   = ann.ip;
            foundPort = ann.tcpPort ? ann.tcpPort : 45846;
            found     = true;
            cv.notify_one();
        });

    {
        std::unique_lock<std::mutex> lk(mu);
        cv.wait_for(lk, std::chrono::seconds(4), [&] { return found; });
    }
    disco.stop();

    if (!found) {
        if (cs->feedback)
            cs->feedback->ShowError(LngStrU8(IDS_LAN_ERR_PEER_NOT_FOUND, "LAN Pair: peer not found on the network. Make sure the other computer is running.").c_str());
        return fail();
    }

    cs->lan_pair_ip   = foundIp;
    cs->lan_pair_port = foundPort;

    // Register password with our own server BEFORE connecting —
    // the remote peer may simultaneously try to connect to us using the same password.
    if (!cs->password.empty()) {
        lanpair::DpapiSecretStore::saveSecret("lanpair-server-pw", cs->password, nullptr);
        if (g_lanFileServer)
            g_lanFileServer->setPassword(cs->password);
    }
    LanFileServerSetTrustedInstaller(cs->lan_pair_trusted_installer);

    {
        std::string s = LngStrU8(IDS_LAN_CONNECTING, "LAN Pair: connecting to {}...");
        const auto p = s.find("{}");
        if (p != std::string::npos) s.replace(p, 2, foundIp);
        ShowStatus(s.c_str());
    }

    lanpair::PairError err;
    auto session = LanPairSession::connect(
        foundIp, foundPort, localId, targetPeerId,
        cs->password,   // empty = use stored trust key
        &err);

    if (!session) {
        std::string msg = LngStrU8(IDS_LAN_ERR_CONN_FAILED, "LAN Pair: connection failed");
        if (!err.message.empty()) msg += " \xe2\x80\x94 " + err.message;
        if (cs->feedback) cs->feedback->ShowError(msg.c_str());
        return fail();
    }

    session->setTimeoutMin(cs->lan_pair_timeout_min);
    session->setTrustedInstaller(cs->lan_pair_trusted_installer);
    cs->lanSession = std::move(session);
    ++g_lanSessionCount;

    ShowStatusId(IDS_LOG_LAN_CONNECTED, nullptr, true);
    return SFTP_OK;
}
#endif // SFTP_EXTRA

int SftpConnect(pConnectSettings ConnectSettings)
{
    int hr = 0;
#if !SFTP_EXTRA
    // The classic build has no PHP Agent and no LAN Pair. A session made for
    // them in the extra build is refused, never tried as SSH.
    if (ConnectSettings->transfermode != static_cast<int>(sftp::TransferMode::ssh_auto)) {
        SFTP_LOG("CONN", "transfer mode %d needs the extra build", ConnectSettings->transfermode);
        if (ConnectSettings->feedback)
            ConnectSettings->feedback->ShowError(LngStrU8(IDS_ERR_NEEDS_EXTRA,
                "This session uses PHP Agent or LAN Pair, which only the extra build of the plugin "
                "has (SFTPplug-...-extra.zip). This build connects over SSH only.").c_str());
        return SFTP_FAILED;
    }
#else
    if (IsLanPairTransport(ConnectSettings)) {
        return LanPairConnect(ConnectSettings);
    }
    if (IsPhpAgentTransport(ConnectSettings)) {
        ShowStatusId(IDS_LOG_PHP_AGENT_MODE, nullptr, true);
        std::string probeError;
        if (PhpAgentProbe(ConnectSettings, probeError) != SFTP_OK) {
            if (ConnectSettings->feedback) {
                if (probeError.empty()) {
                    std::array<char, 256> msgbuf{};
                    const int n = LoadStr(msgbuf, IDS_PHP_PROBE_FAILED);
                    probeError = n > 0 ? msgbuf.data() : "PHP Agent probe failed. Check URL and key.";
                }
                ConnectSettings->feedback->ShowError(probeError);
            }
            return SFTP_FAILED;
        }
        return SFTP_OK;
    }
#endif

    std::array<char, 1024> buf{};
    std::array<char, 250> connecttoserver{};
    std::array<char, 250> progressbuf{};

    int progress = 0;
    unsigned short connecttoport;
    int loop;
    SYSTICKS lasttime = get_sys_ticks();
    auto fail = [&](int code) -> int {
        return CleanupFailedConnect(ConnectSettings, code, &progress, &loop, &lasttime);
    };

    {
        int precheckCode = SFTP_OK;
        if (!ValidateConnectState(ConnectSettings, &precheckCode))
            return precheckCode;
    }

    if (ProgressProcI(PluginNumber, "Connecting...", "-", progress))
        return fail(-9);

    if (!ResolveConnectEndpoint(ConnectSettings, connecttoserver.data(), connecttoserver.size(), &connecttoport)) {
        if (ConnectSettings->proxytype == sftp::Proxy::http ||
            ConnectSettings->proxytype == sftp::Proxy::socks4 ||
            ConnectSettings->proxytype == sftp::Proxy::socks5) {
            if (ConnectSettings->feedback)
                ConnectSettings->feedback->ShowError(LngStrU8(IDS_ERR_INVALID_PROXY, "Invalid proxy server address.").c_str());
            return fail(ConnectSettings->proxytype == sftp::Proxy::http ? -11 : -12);
        }
        if (ConnectSettings->feedback) {
            ConnectSettings->feedback->ShowError(LngStrU8(IDS_ERR_NOT_SUPPORTED, "Function not supported yet!").c_str());
        }
        return fail(-13);
    }
    ShowStatus("========================================");
    ShowStatusId(IDS_CONNECT_TO, ConnectSettings->server, true);

    progress = PROG_SOCKET_CONNECT;

    // One resolver decides what this profile's jump host actually is, so the
    // connect path cannot disagree with what the dialog shows. It refuses
    // rather than returning an empty endpoint, which is what keeps a session
    // with a dangling reference from quietly connecting past the bastion.
    JumpConfig jumpCfg = ResolveJumpConfig(ConnectSettings, inifilename);

    // The jump host is reached straight from this machine: a proxy set on
    // the session as well would be skipped without a word.
    if (jumpCfg.status == JumpConfigStatus::Ready &&
        ConnectSettings->proxytype != sftp::Proxy::notused) {
        jumpCfg.status = JumpConfigStatus::WithProxy;
        jumpCfg.error  = LngStrU8(IDS_JUMP_WITH_PROXY,
            "This session is set to go through both a proxy and a jump host. The "
            "plugin reaches a jump host directly, which would skip the proxy. "
            "Keep one of the two.");
    }

    if (jumpCfg.status != JumpConfigStatus::Disabled &&
        jumpCfg.status != JumpConfigStatus::Ready) {
        ShowStatus(jumpCfg.error.c_str());
        if (ConnectSettings->feedback && !ConnectSettings->jump_refusal_shown) {
            ConnectSettings->jump_refusal_shown = true;
            ConnectSettings->feedback->ShowError(jumpCfg.error, "ProxyJump");
        }
        return fail(-25);
    }

    if (jumpCfg.status == JumpConfigStatus::Ready) {
        // -----------------------------------------------------------------
        // ProxyJump path:
        // 1. TCP + SSH to jump host
        // 2. direct-tcpip channel to target
        // 3. Target SSH session runs over channel (via SEND/RECV callbacks)
        // -----------------------------------------------------------------
        // The jump session is created from g_sshBackend, so the backend has
        // to exist before ConnectViaJumpHost, not only before
        // InitializeSshSession() which runs after the jump host stage.
        EnsureSshBackend();

        JumpHostSettings jump = jumpCfg.endpoint;
        if (!jump.passwordStoreName.empty()) {
            std::string stored = LoadPlainPassword("!", jump.passwordStoreName);
            if (stored.empty()) {
                ShowStatus("Jump host: password not loaded from the password manager");
                if (ConnectSettings->feedback)
                    ConnectSettings->feedback->ShowError(
                        LngStrU8(IDS_ERR_LOAD_PASS, "Failed to load password!"), "ProxyJump");
                return fail(-25);
            }
            const StoredSecret secret = SplitStoredSecret(stored);
            SecureZeroMemory(stored.data(), stored.size());
            jump.password       = secret.accountPassword;
            jump.keyPassphrase  = secret.keyPassphrase;
            jump.secretLabelled = secret.labelled;
        }

        // Target is the server configured in the profile (resolved already
        // in connecttoserver/connecttoport above).
        auto stream = ConnectViaJumpHost(
            ConnectSettings, jump, g_sshBackend.get(),
            ConnectSettings->server, ConnectSettings->customport,
            progress, loop, lasttime);

        if (!stream)
            return fail(-25);

        // Mirror a fingerprint accepted on first connect. Only for a manually
        // configured jump host: this field describes that host, whereas a
        // referenced session keeps its own key under its own section.
        if (ConnectSettings->jump_session_ref.empty())
            ConnectSettings->jump_fingerprint = jump.fingerprint;
        ConnectSettings->transport_stream = std::move(stream);
        // cs->sock has been set to the jump socket by ConnectViaJumpHost.

    } else {
        // -----------------------------------------------------------------
        // Direct / proxy path
        // -----------------------------------------------------------------
        int socketErr = EstablishSocketConnection(ConnectSettings, connecttoserver.data(), connecttoport, progress, loop, lasttime);
        if (socketErr != 0) {
            return fail(socketErr);
        }

        // **********************************************************
        //  Proxy?
        hr = NegotiateProxy(ConnectSettings, connecttoport, progress, loop, lasttime);
        if (hr != 0) return fail(hr);
    }

    EnsureSshBackend();
    hr = InitializeSshSession(ConnectSettings, progress, loop, lasttime, g_sshBackend);
    if (hr != 0) return fail(hr);

    progress = PROG_AUTH_START;
    LoadStr(buf, IDS_SSH_LOGIN);
    if (ProgressProcI(PluginNumber, buf.data(), "-", progress))
        return fail(-80);

    hr = VerifyServerFingerprint(ConnectSettings);
    if (hr != 0) return fail(hr);

    // Ask for user name if none was entered
    if (!EnsureUserNameIfMissing(ConnectSettings))
        return fail(-110);

    hr = PerformAuthentication(ConnectSettings, progress, loop, lasttime, progressbuf.data());
    if (hr != 0) return fail(hr);

    ShowStatusId(IDS_LOG_POST_AUTH_INIT, nullptr, true);
    ShowStatus(ConnectSettings->scponly ? "SCP only mode" : "SFTP mode");
    RunPostAuthAutoDetect(ConnectSettings);

    progress = PROG_SFTP_INIT;

    RunPostAuthUserCommand(ConnectSettings, progressbuf.data(), progress, &loop, &lasttime);

    ResolveScpLargeFileProbe(ConnectSettings);

    progress = PROG_SFTP_INIT;

    if (!InitializeSftpSubsystemIfNeeded(ConnectSettings, progress, &loop, &lasttime))
        return fail(SFTP_FAILED);

    progress = PROG_DONE;

    LoadStr(buf, IDS_GET_DIRECTORY);
    if (ProgressProcI(PluginNumber, buf.data(), "-", progress))
        return fail(SFTP_FAILED);

    CONN_LOG("SftpConnect success");
    return SFTP_OK;
}

void SftpGetServerBasePathW(LPCWSTR DisplayName, LPWSTR RelativePath, size_t maxlen, LPCSTR inifilename)
{
    std::array<char, MAX_PATH> displayNameA{};
    std::array<char, MAX_PATH> server{};
    wilcopy(displayNameA.data(), DisplayName, displayNameA.size() - 1);
    IniGetString(displayNameA.data(), "server", "", server.data(), server.size() - 1, inifilename);
    // LAN Pair and PHP Agent: base path is always root. A PHP Agent server is
    // a URL whose path names the script, not a start folder.
    if (_strnicmp(server.data(), "lanpair://", 10) == 0 ||
        _strnicmp(server.data(), "http://", 7) == 0 ||
        _strnicmp(server.data(), "https://", 8) == 0) {
        wcslcpy(RelativePath, L"/", maxlen);
        return;
    }
    ReplaceBackslashBySlash(server.data());
    // Remove leading sftp://
    if (_strnicmp(server.data(), "sftp://", 7) == 0)
        memmove(server.data(), server.data() + 7, strlen(server.data()) - 6);
    ReplaceBackslashBySlash(server.data());
    char* p = strchr(server.data(), '/');
    if (p)
        iwlcopy(RelativePath, p, maxlen);
    else
        wcslcpy(RelativePath, L"/", maxlen);
}

int codepagelist[kCodepageListCount] = {-1, -2, 0, 1, 2, 1250, 1251, 1252, 1253, 1254, 1255, 1256, 1257, 1258,
                                        936, 950, 932, 949, 874, 437, 850, 20866, -3, -4};

bool SftpConfigureServer(LPCSTR DisplayName, LPCSTR inifilename)
{
    tConnectSettings ConnectSettings{};
    ConnectSettings.dialogforconnection = false;
    return ShowConnectDialog(&ConnectSettings, DisplayName, inifilename);
}

int SftpCloseConnection(pConnectSettings ConnectSettings)
{
    if (!ConnectSettings)
        return SFTP_FAILED;

    // 1. LAN Pair (own transport, not SSH) — quick disconnect.
#if SFTP_EXTRA
    ReleaseLanSession(ConnectSettings);
#endif

    // 2. SCP shell channel (only present in scponly mode). Destructor of
    //    Libssh2Channel sends SSH_MSG_CHANNEL_CLOSE/free with bounded retry.
    if (ConnectSettings->scpShellChannel) {
        ConnectSettings->scpShellChannel.reset();
        ConnectSettings->scpShellMsgBuf.clear();
        ConnectSettings->scpShellErrBuf.clear();
    }

    // 3. SFTP subsystem (only present in SFTP mode). ~Libssh2SftpSession()
    //    sends SFTP_FXP_SHUTDOWN with a bounded retry.
    ConnectSettings->sftpsession.reset();
    ++ConnectSettings->sftpGeneration;

    // 4. SSH session — send SSH_MSG_DISCONNECT once. RFC 4253 §11.1: server
    //    must not reply, so there is nothing to wait for. EAGAIN here means
    //    the SSH packet did not fit in libssh2's send buffer; retry briefly
    //    just to push it into the OS socket buffer (TCP itself handles wire
    //    delivery from there).
    if (ConnectSettings->session) {
        SYSTICKS t0 = get_sys_ticks();
        int rc;
        do {
            rc = ConnectSettings->session->disconnect("Disconnect");
            if (rc != LIBSSH2_ERROR_EAGAIN)
                break;
            if (get_ticks_between(t0) > 200)
                break;   // 200 ms cap — DISCONNECT is ~50 bytes, must fit by now.
            if (ConnectSettings->sock != INVALID_SOCKET) {
                fd_set wfds;
                FD_ZERO(&wfds);
                FD_SET(ConnectSettings->sock, &wfds);
                timeval tv = { 0, 20000 };  // 20 ms
                select(0, nullptr, &wfds, nullptr, &tv);
            }
        } while (true);
        ConnectSettings->session.reset();   // ~Libssh2Session() frees the struct.
    }

    // 5. ProxyJump transport (jump channel + jump session) — destructors
    //    cascade and tear down the inner session/channel cleanly.
    ConnectSettings->transport_stream.reset();

    // 6. TCP socket — graceful close: the OS flushes any pending DISCONNECT
    //    bytes before sending FIN. No artificial Sleep needed.
    if (ConnectSettings->sock != INVALID_SOCKET) {
        closesocket(ConnectSettings->sock);
        ConnectSettings->sock = INVALID_SOCKET;
    }

    // `feedback` stays: a reconnect on these settings needs it to warn about
    // a changed host key. It goes with the settings object.
    return SFTP_FAILED;
}

bool ReconnectSFTPChannelIfNeeded(pConnectSettings ConnectSettings)
{
    if (IsLanPairTransport(ConnectSettings)) {
#if SFTP_EXTRA
        return ConnectSettings->lanSession && ConnectSettings->lanSession->isConnected();
#else
        return false;
#endif
    }
    if (IsPhpAgentTransport(ConnectSettings))
        return true;

    if (ConnectSettings->scponly) {
        // No SFTP subsystem to reconnect, but verify the SSH session and socket are alive.
        // If the socket dropped or the session is gone, do a full reconnect so subsequent
        // ConnectChannel() calls have a live session to work with.
        bool sessionGone = !ConnectSettings->session;
        bool sockLost    = (ConnectSettings->sock == INVALID_SOCKET)
                        || IsSocketError(ConnectSettings->sock);
        if (sessionGone || sockLost) {
            CONN_LOG("ReconnectSFTP(SCP): session/sock lost (gone=%d sockLost=%d), reconnecting",
                     sessionGone ? 1 : 0, sockLost ? 1 : 0);
            ShowStatusId(IDS_LOG_SCP_RECONNECT, nullptr, true);
            SftpCloseConnection(ConnectSettings);
            Sleep(RECONNECT_SLEEP_MS);
            SftpConnect(ConnectSettings);
            CONN_LOG("ReconnectSFTP(SCP): after reconnect session=%s",
                     ConnectSettings->session ? "OK" : "FAILED");
        }
        return ConnectSettings->session != nullptr;
    }
    if (ConnectSettings->neednewchannel || ConnectSettings->sftpsession == nullptr) {
        ConnectSettings->neednewchannel = false;
        SYSTICKS starttime = get_sys_ticks();
        int rc;
        int loop = 0;
        if (ConnectSettings->sftpsession) {
            do {
                rc=ConnectSettings->sftpsession->shutdown();
            } while (rc == LIBSSH2_ERROR_EAGAIN && get_ticks_between(starttime) < RECONNECT_SFTP_TIMEOUT_MS);
            ConnectSettings->sftpsession.reset();
            ++ConnectSettings->sftpGeneration;
        }

        // Waits on the socket between attempts and gives up after the same
        // time as the first connect does; a full reconnect follows then.
        const SYSTICKS initStart = get_sys_ticks();
        if (ConnectSettings->session)
            do {
                ConnectSettings->sftpsession = nullptr;
                if (ProgressLoop("Reconnect SFTP channel", 0, 100, &loop, &starttime))
                    break;
                auto sftpPtr = ConnectSettings->session->sftpInit(ConnectSettings->sftpservercommand);
                if (sftpPtr) {
                    ConnectSettings->sftpsession = std::move(sftpPtr);
                } else if (ConnectSettings->session->lastErrno() != LIBSSH2_ERROR_EAGAIN ||
                           get_ticks_between(initStart) > SFTP_INIT_TIMEOUT_MS) {
                    break;
                } else {
                    WaitForSshIo(ConnectSettings);
                }
            } while (!ConnectSettings->sftpsession);

        // Reconnect the full connection when subsystem recovery fails.
        if (!ConnectSettings->sftpsession) {
            ShowStatusId(IDS_LOG_RECONNECT, nullptr, true);
            SftpCloseConnection(ConnectSettings);
            Sleep(RECONNECT_SLEEP_MS);
            SftpConnect(ConnectSettings);
        }
        ConnectSettings->neednewchannel = ConnectSettings->sftpsession == nullptr;
    }
    return !ConnectSettings->neednewchannel;
}
