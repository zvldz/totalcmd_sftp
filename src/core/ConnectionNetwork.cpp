#include "global.h"
#include <windows.h>
#include <ws2tcpip.h>
#include <array>
#include <format>
#include "SftpClient.h"
#include "SftpInternal.h"
#include "PluginEntryPoints.h"
#include "CoreUtils.h"
#include "res/resource.h"
#include "ConnectionNetwork.h"
#include "UnicodeHelpers.h"

int EstablishSocketConnection(pConnectSettings ConnectSettings, LPCSTR connecttoserver, unsigned short connecttoport, int& progress, int& loop, SYSTICKS& lasttime)
{
    ADDRINFOW hints{};
    bool connected = false;
    bool cancelled = false;
    switch (ConnectSettings->protocoltype) {
    case 1:
        hints.ai_family = AF_INET;
        break;
    case 2:
        hints.ai_family = AF_INET6;
        break;
    default:
        hints.ai_family = AF_UNSPEC;
        break;
    }
    hints.ai_socktype = SOCK_STREAM;
    const std::wstring portStr = std::to_wstring(connecttoport);
    std::array<char, 256> progressBuf{};
    // Looked up in Unicode: a host name with characters outside the Windows
    // codepage would not survive the ANSI form.
    ADDRINFOW* res = nullptr;
    SFTP_LOG("NET", "TCP connect to '%s:%d'", connecttoserver, connecttoport);
    const SYSTICKS connectStart = get_sys_ticks();
    if (GetAddrInfoW(unicode_util::internal_to_wide(connecttoserver).c_str(), portStr.c_str(), &hints, &res) != 0) {
        SFTP_LOG("NET", "DNS lookup failed (WSA error %d)", WSAGetLastError());
        ShowErrorId(IDS_ERR_GETADDRINFO);
        if (LogProc || LogProcW) {
            const std::string msg = std::format("SFTP: DNS lookup failed for '{}' (WSA error {})", connecttoserver, WSAGetLastError());
            LogProcI(PluginNumber, MSGTYPE_IMPORTANTERROR, msg.c_str());
        }
        return -20;
    }
    ConnectSettings->sock = INVALID_SOCKET;
    int connectError = 0;   // why the last address failed, for the log
    for (ADDRINFOW* ai = res; ai && !cancelled; ai = ai->ai_next) {
        closesocket(ConnectSettings->sock);
        ConnectSettings->sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (ConnectSettings->sock == INVALID_SOCKET)
            continue;
        // Address and port as connected, an IPv6 address in brackets.
        std::array<char, NI_MAXHOST> host{};
        std::array<char, NI_MAXSERV> port{};
        if (getnameinfo(ai->ai_addr, static_cast<socklen_t>(ai->ai_addrlen), host.data(), static_cast<DWORD>(host.size()),
                        port.data(), static_cast<DWORD>(port.size()), NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
            const bool v6 = ai->ai_family == AF_INET6;
            const std::string address = std::format("{}{}{}:{}", v6 ? "[" : "", host.data(), v6 ? "]" : "", port.data());
            ShowStatus(("IP address: " + address).c_str());
            SFTP_LOG("NET", "trying %s", address.c_str());
        }

        int nodelay = 1;
        setsockopt(ConnectSettings->sock, IPPROTO_TCP, TCP_NODELAY,
                   reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));
        EnableTcpKeepAlive(ConnectSettings->sock);
        SetBlockingSocket(ConnectSettings->sock, false);
        connected = connect(ConnectSettings->sock, ai->ai_addr, (int)ai->ai_addrlen) == 0;
        connectError = connected ? 0 : WSAGetLastError();
        if (!connected && connectError == WSAEWOULDBLOCK) {
            while (true) {
                if (IsSocketWritable(ConnectSettings->sock)) {
                    connected = true;
                    break;
                }
                if (IsSocketError(ConnectSettings->sock)) {
                    // A failed non-blocking connect keeps its reason on the
                    // socket: 10060 timed out, 10061 refused.
                    int soError = 0;
                    int soLen = sizeof(soError);
                    getsockopt(ConnectSettings->sock, SOL_SOCKET, SO_ERROR,
                               reinterpret_cast<char*>(&soError), &soLen);
                    connectError = soError;
                    break;
                }
                // Cancel ends the connect, not just the wait on this address.
                if (ProgressLoop(progressBuf.data(), 0, progress, &loop, &lasttime)) {
                    cancelled = true;
                    break;
                }
            }
        }
        if (connected)
            break;
    }
    FreeAddrInfoW(res);
    SFTP_LOG("NET", "TCP connect %s after %d ms (WSA error %d)",
             connected ? "done" : cancelled ? "cancelled" : "failed",
             static_cast<int>(get_ticks_between(connectStart)), connected ? 0 : connectError);

    if (!connected) {
        // A connect the user cancelled ends without an error box.
        if (cancelled) {
            ShowStatus("Connect cancelled");
            return -30;
        }
        if (ConnectSettings->proxytype != sftp::Proxy::notused)
            ShowErrorId(IDS_ERR_PROXYCONNECT);
        else
            ShowErrorId(IDS_ERR_SERVERCONNECT);
        if (LogProc || LogProcW) {
            const std::string msg = std::format("SFTP: TCP connect failed to '{}:{}' (WSA error {})", connecttoserver, connecttoport, WSAGetLastError());
            LogProcI(PluginNumber, MSGTYPE_IMPORTANTERROR, msg.c_str());
        }
        return -30;
    }
    return 0;
}

bool InitializeSftpSubsystemIfNeeded(pConnectSettings ConnectSettings, int progress, int* loop, SYSTICKS* lasttime)
{
    if (ConnectSettings->scponly)
        return true;

    std::array<char, 1024> buf{};
    char* errmsg = nullptr;
    int errmsg_len = 0;
    const std::string& serverCommand = ConnectSettings->sftpservercommand;
    ShowStatusId(IDS_LOG_SFTP_INIT, nullptr, true);
    if (serverCommand.empty())
        SFTP_LOG("CONN", "Initializing SFTP subsystem");
    else
        SFTP_LOG("CONN", "Initializing SFTP via the configured server command");
    ShowStatusId(IDS_SESSION_STARTUP, " (SFTP)", true);
    // A host with no SFTP subsystem — dropbear on a camera or a router —
    // may never answer the request, and the call keeps saying "not yet".
    // The wait is bounded so such a host fails instead of hanging.
    const SYSTICKS sftpInitStart = get_sys_ticks();
    bool sftpInitTimedOut = false;
    do {
        ConnectSettings->sftpsession = nullptr;
        if (ProgressLoop(buf.data(), progress, progress + 10, loop, lasttime))
            break;
        auto sftpPtr = ConnectSettings->session->sftpInit(serverCommand);
        if (sftpPtr) {
            ConnectSettings->sftpsession = std::move(sftpPtr);
        } else if (ConnectSettings->session->lastErrno() != LIBSSH2_ERROR_EAGAIN) {
            break;
        } else if (get_ticks_between(sftpInitStart) > SFTP_INIT_TIMEOUT_MS) {
            sftpInitTimedOut = true;
            break;
        }
        // Waits in the direction libssh2 is blocked on: a request still
        // being sent waits for the socket to take it, not for a reply.
        WaitForSshIo(ConnectSettings, SOCKET_READ_POLL_MS);
    } while (!ConnectSettings->sftpsession);

    if (!ConnectSettings->sftpsession) {
        ConnectSettings->session->lastError(&errmsg, &errmsg_len, false);
        ShowStatusId(IDS_ERR_INIT_SFTP, errmsg, true);
        SFTP_LOG("CONN", "SFTP init failed%s: %s", sftpInitTimedOut ? " (no answer)" : "",
                 errmsg ? errmsg : "(null)");
        // With a server command set, the command is the likeliest culprit.
        // Without one, it is a host that offers only a shell, and the
        // session has a mode for exactly that; say so rather than leave a
        // bare "could not initialise".
        ShowErrorId(serverCommand.empty() ? IDS_ERR_NO_SFTP_HINT : IDS_ERR_SFTP_SERVER_CMD);
        if (LogProc || LogProcW) {
            const std::string msg = std::format("SFTP: SFTP subsystem init failed: {}", errmsg ? errmsg : "(no details)");
            LogProcI(PluginNumber, MSGTYPE_IMPORTANTERROR, msg.c_str());
        }
        return false;
    }

    ConnectSettings->session->setBlocking(0);
    return true;
}
