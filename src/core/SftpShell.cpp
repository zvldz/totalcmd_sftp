#include "global.h"
#include <windows.h>
#include <ws2tcpip.h>
#include <array>
#include <string>
#include <vector>
#include <algorithm>
#include <chrono>
#include <random>
#include <string_view>
#include "SftpClient.h"
#include "PluginEntryPoints.h"
#include "fsplugin.h"
#include "ServerRegistry.h"
#include "res/resource.h"
#include "CoreUtils.h"
#include "SftpInternal.h"
#include "TerminalText.h"
#include "UnicodeHelpers.h"

namespace {

// Timeout constants (in milliseconds)
constexpr DWORD kShellFlushTimeoutMs      = 1000;
constexpr DWORD kShellEofTimeoutMs        = 3000;
constexpr DWORD kShellCloseTimeoutMs      = 3000;
constexpr DWORD kShellFreeTimeoutMs       = 5000;
constexpr DWORD kScpPtyOpenTimeoutMs      = 10000;
constexpr DWORD kScpShellOpenTimeoutMs    = 15000;
constexpr DWORD kChannelReplyTimeoutMs    = 15000;
constexpr DWORD kShellEagainGraceIdleMs   = 1000;
constexpr DWORD kShellEagainGraceTotalMs  = 5000;
constexpr DWORD kQuoteProgressStartMs     = 2000;

// Trim leading whitespace and control characters
std::string_view TrimLeft(std::string_view sv) noexcept
{
    const auto pos = sv.find_first_not_of(" \t\r\n");
    return (pos == std::string_view::npos) ? std::string_view{} : sv.substr(pos);
}

// Check if line looks like an echoed command or prompt
bool IsEchoOrPromptLine(std::string_view line) noexcept
{
    line = TrimLeft(line);
    if (line.empty())
        return false;
    if (line.substr(0, 5) == "echo " || line.find("$ echo ") != std::string_view::npos)
        return true;
    return false;
}

// Terminal control sequences out. Backslashes stay: the listing asks `ls`
// for names as they are, so "\101" in a name is those four characters.
void StripEscapeSequences(std::string& str)
{
    str = terminal_text::StripControls(str);
}

void StripEscapeSequencesLocalA(LPSTR msgbuf)
{
    if (!msgbuf || !msgbuf[0])
        return;
    std::string tmp(msgbuf);
    StripEscapeSequences(tmp);
    strlcpy(msgbuf, tmp.c_str(), tmp.size() + 1);
}

} // anonymous namespace

void StripEscapeSequences(LPSTR msgbuf)
{
    if (!msgbuf)
        return;
    StripEscapeSequencesLocalA(msgbuf);
}

void DisconnectShell(ISshChannel* channel, int* exitStatus)
{
    if (exitStatus)
        *exitStatus = -1;
    if (!channel)
        return;
    WaitForOperation([channel] { return channel->flush(); }, kShellFlushTimeoutMs, nullptr);
    WaitForOperation([channel] { return channel->sendEof(); }, kShellEofTimeoutMs, nullptr);
    WaitForOperation([channel] { return channel->waitEof(); }, kShellEofTimeoutMs, nullptr);
    WaitForOperation([channel] { return channel->channelClose(); }, kShellCloseTimeoutMs, nullptr);
    if (exitStatus &&
        WaitForOperation([channel] { return channel->waitClosed(); }, kShellCloseTimeoutMs, nullptr) == 0)
        *exitStatus = channel->getExitStatus();
    // Explicit drained channelFree() — see DisconnectShell rationale.
    WaitForOperation([channel] { return channel->channelFree(); }, kShellFreeTimeoutMs, nullptr);
}

std::unique_ptr<ISshChannel> ConnectChannel(ISshSession* session, SOCKET sock)
{
    if (!session)
        return nullptr;

    session->setBlocking(0);
    if (sock != INVALID_SOCKET)
        SetBlockingSocket(sock, false);

    const auto start = std::chrono::steady_clock::now();
    std::unique_ptr<ISshChannel> channel;

    do {
        channel = session->openChannel();
        if (channel)
            break;

        const int err = session->lastErrno();
        if (err != LIBSSH2_ERROR_EAGAIN)
            break;

        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        if (elapsed > 12000) // kOpenChannelTimeoutMs
            break;

        if (sock != INVALID_SOCKET)
            IsSocketReadable(sock);
        else
            Sleep(50);
    } while (!channel);

    if (!channel) {
        std::string errmsg = "Unable to open a session";
        const int err = session->lastErrno();
        switch (err) {
            case LIBSSH2_ERROR_ALLOC:          errmsg += ": internal memory allocation call failed"; break;
            case LIBSSH2_ERROR_SOCKET_SEND:    errmsg += ": Unable to send data on socket"; break;
            case LIBSSH2_ERROR_SOCKET_RECV:    errmsg += ": Unable to receive data on socket"; break;
            case LIBSSH2_ERROR_CHANNEL_FAILURE: errmsg += ": Channel failure"; break;
            default:                            errmsg += ": Error code " + std::to_string(err); break;
        }
        ShowStatus(errmsg.c_str());
        return nullptr;
    }

    channel->setBlocking(0);
    return channel;
}

bool SendChannelCommandNoEof([[maybe_unused]] ISshSession* session, ISshChannel* channel, const char* command, SOCKET sock)
{
    pConnectSettings waitCtx = nullptr;
    tConnectSettings tempCtx{};
    if (sock != INVALID_SOCKET) {
        tempCtx.sock = sock;
        waitCtx = &tempCtx;
    }
    int rc = WaitForOperation([&] { return channel->exec(command); }, SSH_AUTH_STAGE_TIMEOUT_MS, waitCtx);
    if (rc < 0)
        return false;

    rc = WaitForOperation([&] { return channel->flush(); }, SSH_AUTH_STAGE_TIMEOUT_MS, waitCtx);
    return rc >= 0;
}

bool SendChannelCommand(ISshSession* session, ISshChannel* channel, const char* command, SOCKET sock)
{
    if (!SendChannelCommandNoEof(session, channel, command, sock))
        return false;
    pConnectSettings waitCtx = nullptr;
    tConnectSettings tempCtx{};
    if (sock != INVALID_SOCKET) {
        tempCtx.sock = sock;
        waitCtx = &tempCtx;
    }
    WaitForOperation([&] { return channel->sendEof(); }, SSH_AUTH_STAGE_TIMEOUT_MS, waitCtx);
    return true;
}

namespace {

constexpr char kLoginNoiseMarker[] = "__SFTPPLUG_LOGIN_NOISE__";
constexpr DWORD kLoginNoiseTimeoutMs = 10000;
constexpr size_t kLoginNoiseMax = 16384;

// A channel whose first output bytes were read ahead to compare them with the
// login script's text and turned out to be something else: they are handed
// back to the reader first, then the channel's own output follows.
class PendingOutputChannel final : public ISshChannel {
public:
    PendingOutputChannel(std::unique_ptr<ISshChannel> inner, std::string pending)
        : inner_(std::move(inner)), pending_(std::move(pending)) {}

    ssize_t read(char* buf, size_t len) override
    {
        if (pos_ < pending_.size()) {
            const size_t n = (std::min)(len, pending_.size() - pos_);
            memcpy(buf, pending_.data() + pos_, n);
            pos_ += n;
            return static_cast<ssize_t>(n);
        }
        return inner_->read(buf, len);
    }
    ssize_t readStderr(char* buf, size_t len) override { return inner_->readStderr(buf, len); }
    ssize_t write(const char* buf, size_t len) override { return inner_->write(buf, len); }
    ssize_t writeEx(int streamId, const char* buf, size_t len) override { return inner_->writeEx(streamId, buf, len); }
    int exec(const char* cmd) override { return inner_->exec(cmd); }
    int shell() override { return inner_->shell(); }
    int sendEof() override { return inner_->sendEof(); }
    int eof() override { return pos_ < pending_.size() ? 0 : inner_->eof(); }
    int waitEof() override { return inner_->waitEof(); }
    int channelClose() override { return inner_->channelClose(); }
    int waitClosed() override { return inner_->waitClosed(); }
    int channelFree() override { return inner_->channelFree(); }
    int flush() override { return inner_->flush(); }
    int getExitStatus() override { return inner_->getExitStatus(); }
    void setBlocking(int blocking) override { inner_->setBlocking(blocking); }
    int requestPty(const char* term, unsigned termLen, const char* modes, unsigned modesLen,
                   int width, int height, int widthPx, int heightPx) override
    {
        return inner_->requestPty(term, termLen, modes, modesLen, width, height, widthPx, heightPx);
    }

private:
    std::unique_ptr<ISshChannel> inner_;
    std::string pending_;
    size_t pos_ = 0;
};

} // anonymous namespace

void LearnLoginNoise(pConnectSettings cs)
{
    if (!cs || !cs->session || !cs->loginNoiseHandling || cs->loginNoiseState != 0)
        return;
    cs->loginNoiseState = 1;

    // A bare `echo` is understood by every shell, Windows ones included. A
    // restricted shell that refuses it leaves the connection as one without
    // noise.
    auto channel = ConnectChannel(cs->session.get(), cs->sock);
    if (!channel)
        return;
    const std::string command = std::string("echo ") + kLoginNoiseMarker;
    if (!SendChannelCommand(cs->session.get(), channel.get(), command.c_str(), cs->sock))
        return;

    std::string out;
    std::array<char, 1024> buf{};
    const SYSTICKS start = get_sys_ticks();
    while (out.size() < kLoginNoiseMax) {
        const ssize_t rc = channel->read(buf.data(), buf.size());
        if (rc > 0) {
            out.append(buf.data(), static_cast<size_t>(rc));
            continue;
        }
        if (rc != LIBSSH2_ERROR_EAGAIN || channel->eof())
            break;
        if (get_ticks_between(start) > static_cast<int>(kLoginNoiseTimeoutMs))
            break;
        WaitForSshIo(cs);
    }

    const size_t at = out.find(kLoginNoiseMarker);
    if (at == std::string::npos || (at > 0 && out[at - 1] != '\n')) {
        SFTP_LOG("SHELL", "login script check: no answer to echo, taken as quiet");
        return;
    }
    if (at == 0) {
        SFTP_LOG("SHELL", "login script check: quiet");
        return;
    }
    cs->loginNoise = out.substr(0, at);
    cs->loginNoiseState = 2;
    SFTP_LOG("SHELL", "login script prints %zu bytes before every command; cut off", at);
}

bool SendExecCommand(pConnectSettings cs, std::unique_ptr<ISshChannel>& channel, const char* command, bool sendEof)
{
    if (!cs || !channel)
        return false;
    LearnLoginNoise(cs);
    const bool sent = sendEof
        ? SendChannelCommand(cs->session.get(), channel.get(), command, cs->sock)
        : SendChannelCommandNoEof(cs->session.get(), channel.get(), command, cs->sock);
    if (!sent || cs->loginNoiseState != 2)
        return sent;

    // The login script's text comes first, before the command runs. Only an
    // exact match is dropped; whatever else arrived is given back to the
    // reader unchanged.
    const std::string& noise = cs->loginNoise;
    std::string got;
    std::array<char, 1024> buf{};
    const SYSTICKS start = get_sys_ticks();
    while (got.size() < noise.size()) {
        const ssize_t rc = channel->read(buf.data(), (std::min)(buf.size(), noise.size() - got.size()));
        if (rc > 0) {
            got.append(buf.data(), static_cast<size_t>(rc));
            if (noise.compare(0, got.size(), got) != 0)
                break;
            continue;
        }
        if (rc != LIBSSH2_ERROR_EAGAIN || channel->eof())
            break;
        if (get_ticks_between(start) > static_cast<int>(kLoginNoiseTimeoutMs))
            break;
        WaitForSshIo(cs);
    }
    if (got == noise)
        return true;
    SFTP_LOG("SHELL", "output did not start with the login script's text (%zu of %zu bytes read); kept",
             got.size(), noise.size());
    if (!got.empty())
        channel = std::make_unique<PendingOutputChannel>(std::move(channel), std::move(got));
    return true;
}

// The command's exit status decides: a server may write a banner or a
// warning to stderr for a command that worked. What it wrote there is shown
// when the command failed.
bool GetChannelCommandReply(pConnectSettings cs, std::unique_ptr<ISshChannel>& channelOwner, const char* command)
{
    std::string stderrText;
    if (!SendExecCommand(cs, channelOwner, command, true))
        return false;
    ISshChannel* channel = channelOwner.get();
    const SOCKET sock = cs->sock;

    const auto start = std::chrono::steady_clock::now();
    std::array<char, 1024> buf{};
    std::array<char, 1024> errbuf{};

    while (!channel->eof()) {
        const int errRc = channel->readStderr(errbuf.data(), errbuf.size() - 1);
        if (errRc > 0 && stderrText.size() < 4096)
            stderrText.append(errbuf.data(), static_cast<size_t>(errRc));

        const int rc = channel->read(buf.data(), buf.size() - 1);
        if (rc == LIBSSH2_ERROR_EAGAIN || errRc == LIBSSH2_ERROR_EAGAIN) {
            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start).count();
            if (elapsed > kChannelReplyTimeoutMs)
                break;
            if (sock != INVALID_SOCKET)
                IsSocketReadable(sock);
            else
                Sleep(50);
        } else if (rc < 0 && errRc < 0 && rc != LIBSSH2_ERROR_EAGAIN && errRc != LIBSSH2_ERROR_EAGAIN) {
            break; // hard error
        }
    }

    // The status arrives after the output and before the channel closes.
    if (!channel->eof() ||
        WaitForOperation([&] { return channel->waitClosed(); }, kShellCloseTimeoutMs, nullptr) != 0)
        return false;
    const int status = channel->getExitStatus();
    if (status != 0 && !stderrText.empty()) {
        StripEscapeSequences(stderrText.data());
        ShowStatus(stderrText.c_str());
    }
    return status == 0;
}

bool EnsureScpShell(pConnectSettings cs)
{
    if (!cs || !cs->session)
        return false;

    cs->session->setBlocking(0);
    if (cs->sock != INVALID_SOCKET)
        SetBlockingSocket(cs->sock, false);

    if (cs->scpShellChannel) {
        if (cs->sock == INVALID_SOCKET || IsSocketError(cs->sock) || cs->scpShellChannel->eof()) {
            CloseScpShell(cs);
        } else {
            return true;
        }
    }

    auto channel = ConnectChannel(cs->session.get(), cs->sock);
    if (!channel)
        return false;

    // Request PTY
    int ptyRc = WaitForOperation([&] {
        // A wide terminal, because the shell echoes back what it is sent and the
        // reader tells output from that echo by the markers wrapped around each
        // command. At 80 columns a command with a full path wraps, the tail
        // carries the end marker, and the reading stops before any output is
        // seen — a listing then looks like an empty directory and a transfer
        // like an empty file.
        // The terminal starts with echo off (ECHO = 0, then TTY_OP_END), so
        // even a host without `stty` does not send the commands back.
        static constexpr char kModes[] = { 53, 0, 0, 0, 0, 0 };
        return channel->requestPty("vt102", 5, kModes, sizeof(kModes), 1000, 40, 8000, 480);
    }, kScpPtyOpenTimeoutMs, cs);

    if (ptyRc < 0 && ptyRc != LIBSSH2_ERROR_EAGAIN) {
        return false;
    }

	// Start shell
    int shellRc = WaitForOperation([&] { return channel->shell(); }, kScpShellOpenTimeoutMs, cs);
    if (shellRc < 0) {
        return false;
    }

    // Servers (e.g., home.pl) lose the first login if we send it immediately.
    // We give the shell time to load /etc/profile and the MOTD.
    Sleep(500); 

    cs->scpShellChannel = std::move(channel);
    cs->scpShellMsgBuf.clear();
    cs->scpShellErrBuf.clear();

    // The commands sent here are written for a POSIX shell; a login shell
    // that is csh, tcsh or fish reads `2>/dev/null` or `$?` its own way, so
    // the shell is replaced by /bin/sh first. A restricted shell that refuses
    // keeps running, and the commands work as far as it understands them.
    // Then the terminal's echo is silenced. Everything sent comes back
    // otherwise, and the reader tells a command's output from that echo by
    // the markers around it — an echo long enough to be broken up defeats
    // that, and an upload carries its data inside the command line, where no
    // terminal width is enough. A shell without `stty` ignores this.
    {
        WriteShellCommand(cs, "exec /bin/sh\nstty -echo 2>/dev/null\n", kScpShellOpenTimeoutMs);
        // Let the command run, then drop whatever it echoed on its way out.
        Sleep(200);
        std::array<char, 1024> drain{};
        while (cs->scpShellChannel->read(drain.data(), drain.size()) > 0) {
        }
        cs->scpShellMsgBuf.clear();
        cs->scpShellErrBuf.clear();
    }
    return true;
}

bool WriteShellCommand(pConnectSettings cs, const std::string& command, DWORD timeoutMs)
{
    if (!cs || !cs->scpShellChannel)
        return false;
    if (!ShellCommandIsSafe(command)) {
        SFTP_LOG("SHELL", "Command with a control character not sent");
        ShowStatus("A name contains a control character; not sent to the shell");
        return false;
    }
    const auto start = std::chrono::steady_clock::now();
    size_t written = 0;
    while (written < command.size()) {
        const int rc = static_cast<int>(cs->scpShellChannel->write(command.data() + written,
                                                                   command.size() - written));
        if (rc > 0) {
            written += static_cast<size_t>(rc);
            continue;
        }
        if (rc != LIBSSH2_ERROR_EAGAIN)
            return false;
        if (std::chrono::steady_clock::now() - start > std::chrono::milliseconds(timeoutMs))
            return false;
        if (cs->sock != INVALID_SOCKET)
            WaitForSshIo(cs);
        else
            Sleep(25);
    }
    return true;
}

std::string ShellMarker(const char* base)
{
    std::random_device rd;
    char nonce[17];
    _snprintf_s(nonce, sizeof(nonce), _TRUNCATE, "%08x%08x", rd(), rd());
    return std::string(base) + nonce;
}

std::string ShellEchoMarker(const std::string& marker)
{
    const size_t cut = (std::min)(marker.size(), size_t{4});
    return "echo \"" + marker.substr(0, cut) + "\"\"" + marker.substr(cut) + "\"";
}

void CloseScpShell(pConnectSettings cs)
{
    if (!cs || !cs->scpShellChannel)
        return;

    if (cs->session && cs->sock != INVALID_SOCKET) {
        cs->session->setBlocking(0);
        cs->scpShellChannel->setBlocking(0);

        if (cs->scp_fast_close_required) {
            cs->scpShellChannel->channelClose();
            // ~Libssh2Channel() handles channelFree on scope exit.
        } else {
            DisconnectShell(cs->scpShellChannel.get());
        }
    }
    cs->scpShellChannel.reset();
    cs->scpShellMsgBuf.clear();
    cs->scpShellErrBuf.clear();
}

bool ScpReadCommandOutput(pConnectSettings cs, const char* endMarker,
                           std::vector<std::string>& outLines,
                           DWORD timeoutMs, const char* beginMarker,
                           std::string* endLineOut)
{
    if (endLineOut)
        endLineOut->clear();

    if (!cs || !cs->scpShellChannel || !endMarker)
        return false;

    const std::string endMarkerStr(endMarker);
    const std::string beginMarkerStr(beginMarker ? beginMarker : "");
    const bool hasBegin = !beginMarkerStr.empty();

    // A listing line holds a name and, for a link, its target: two paths of
    // up to 4096 bytes each, so the line buffer leaves room for both.
    std::vector<char> line(65536);
    // `timeoutMs` is how long the command may stay silent, not how long it
    // may run: `ls -l` of a large folder prints nothing until it has sorted
    // it, and a long listing keeps coming. Lines are read a second at a
    // time so Esc and the channel closing are seen while it is quiet.
    auto lastLine = std::chrono::steady_clock::now();
    bool gotBegin = !hasBegin;
    bool gotEnd = false;

    for (;;) {
        if (!ReadChannelLine(cs->scpShellChannel.get(),
                             line.data(), line.size() - 1,
                             cs->scpShellMsgBuf, cs->scpShellErrBuf, cs->sock, 1000, 1000)) {
            if (cs->scpShellChannel->eof() || EscapePressed())
                break;
            const auto quiet = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - lastLine).count();
            if (quiet > static_cast<long long>(timeoutMs))
                break;
            continue;
        }
        lastLine = std::chrono::steady_clock::now();
        std::string lineStr(line.data());
        StripEscapeSequences(lineStr);
        std::string_view trimmed = TrimLeft(lineStr);

        if (trimmed.empty())
            continue;

        // A terminal that still echoes shows the marker first inside the
        // echoed command, then again as the command's output; neither is
        // output to keep.
        if (hasBegin && trimmed.find(beginMarkerStr) != std::string_view::npos) {
            gotBegin = true;
            continue;
        }
        if (!gotBegin)
            continue;

        // The shell may still echo what it was sent, and that echo carries
        // every marker the command mentions — including the end one, with a
        // literal "$?" where the status would be. Taken for the real thing it
        // ends the reading at once and reports a status of zero, so it is
        // skipped before either test below.
        if (IsEchoOrPromptLine(trimmed))
            continue;

        // The command ends by echoing the marker, and whatever the command
        // wanted to report rides on that same line. It is handed back rather
        // than dropped, so callers can read an exit status from it.
        if (trimmed.substr(0, endMarkerStr.size()) == endMarkerStr) {
            gotEnd = true;
            if (endLineOut)
                endLineOut->assign(trimmed);
            break;
        }
        if (trimmed.find(endMarkerStr) != std::string_view::npos) {
            gotEnd = true;
            if (endLineOut)
                endLineOut->assign(trimmed);
            break;
        }

        outLines.push_back(std::move(lineStr));
        if (EscapePressed())
            break;
    }

    return gotEnd && gotBegin;
}

bool ReadChannelLine(ISshChannel* channel, char* line, size_t lineLen,
                     std::string& msgbuf, std::string& errbuf, SOCKET sock,
                     DWORD idleTimeoutMs, DWORD totalTimeoutMs)
{
    const auto start = std::chrono::steady_clock::now();
    auto lastData = start;
    bool endReceived = false;
    bool detectingCrLf = true;
    int consecutiveEagain = 0;

    // Stack buffers for raw channel reads — sized to match the old per-call chunk.
    char tmpbuf[4096];
    char tmperr[2048];

    while (true) {
        const auto now = std::chrono::steady_clock::now();
        const auto idle = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastData).count();
        const auto total = std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count();
        if (idle > static_cast<long long>(idleTimeoutMs) || total > static_cast<long long>(totalTimeoutMs))
            return false;

        if (channel->eof())
            endReceived = true;

        const int rcerr = static_cast<int>(channel->readStderr(tmperr, sizeof(tmperr) - 1));
        const int rc    = static_cast<int>(channel->read(tmpbuf, sizeof(tmpbuf) - 1));

        if (rcerr > 0) {
            errbuf.append(tmperr, rcerr);
            lastData = now;
            consecutiveEagain = 0;
        }
        if (rc > 0) {
            msgbuf.append(tmpbuf, rc);
            lastData = now;
            consecutiveEagain = 0;
        }

        // Extract the first complete line from the accumulation buffer.
        const size_t pos = msgbuf.find('\n');
        if (pos != std::string::npos) {
            size_t lineEnd = pos;
            if (pos > 0 && msgbuf[pos - 1] == '\r') {
                if (detectingCrLf && global_detectcrlf == -1)
                    global_detectcrlf = 1;
                lineEnd = pos - 1;
            } else if (detectingCrLf && global_detectcrlf == -1) {
                global_detectcrlf = 0;
            }
            const size_t copyLen = (std::min)(lineEnd, lineLen - 1);
            msgbuf.copy(line, copyLen, 0);
            line[copyLen] = '\0';
            StripEscapeSequences(line);
            msgbuf.erase(0, pos + 1);
            return true;
        }

        // EOF was seen before these reads, so all the output is already in
        // libssh2's buffers: reads that bring nothing mean it is used up,
        // whether they say 0 or EAGAIN.
        if (endReceived && rc <= 0 && rcerr <= 0) {
            if (!msgbuf.empty() && msgbuf[0] != '\r' && msgbuf[0] != '\n') {
                // Flush the remaining partial line (no trailing newline from the server).
                const size_t copyLen = (std::min)(msgbuf.size(), lineLen - 1);
                msgbuf.copy(line, copyLen, 0);
                line[copyLen] = '\0';
                StripEscapeSequences(line);
                msgbuf.clear();
                return true;
            }
            return false;
        }

        // EOF that came in with these reads: one more pass drains what came
        // with it and ends, nothing is left to wait for.
        if (!endReceived && channel->eof())
            continue;

        if (rc == LIBSSH2_ERROR_EAGAIN || rc == 0) {
            ++consecutiveEagain;
            if (sock != INVALID_SOCKET)
                IsSocketReadable(sock);
            else
                Sleep(consecutiveEagain > 20 ? 200 : 50);
        }
    }
}

// A host that allows no exec channel (forced shell transfer mode) runs the
// command on the persistent shell instead: its output goes to `reply` or the
// log as over an exec channel, and its exit status is returned (-1 when the
// shell gave none).
static int QuoteOnPersistentShell(pConnectSettings cs, const std::string& fullCmd,
                                  char* reply, size_t replylen, bool showWide)
{
    std::vector<std::string> lines;
    int exitCode = -1;
    if (!ShellRunPersistentCommand(cs, fullCmd, lines, &exitCode))
        return -1;
    for (auto& line : lines) {
        StripEscapeSequences(line.data());
        line.resize(strlen(line.c_str()));
        if (!reply) {
            if (showWide) {
                std::vector<wchar_t> wline(line.size() + 1);
                CopyStringA2W(cs, line.c_str(), wline.data(), wline.size(), false);
                ShowStatusW(wline.data());
            } else {
                ShowStatus(line.c_str());
            }
        } else {
            if (reply[0])
                strlcat(reply, "\r\n", replylen);
            strlcat(reply, line.c_str(), replylen);
        }
    }
    SFTP_LOG("SHELL", "Quote command on the persistent shell: rc=%d", exitCode);
    return exitCode;
}

int SftpQuoteCommand2(pConnectSettings cs, const char* remotedir, const char* cmd,
                      char* reply, size_t replylen,
                      DWORD idleTimeoutMs, DWORD totalTimeoutMs)
{
    if (reply && replylen > 0)
        reply[0] = '\0';

    if (!cs)
        return -1;

    std::string dirname, cmdname;
    if (cs->utf8names) {
        if (remotedir) {
            std::wstring wtmp(wdirtypemax, L'\0');
            std::string tmp(wdirtypemax, '\0');
            MultiByteToWideChar(CP_ACP, 0, remotedir, -1, wtmp.data(), static_cast<int>(wtmp.size()));
            wcslcpytoutf8(tmp.data(), wtmp.data(), tmp.size() - 1);
            dirname = tmp.c_str();
        }
        std::wstring wtmp2(wdirtypemax, L'\0');
        std::string tmp2(wdirtypemax, '\0');
        MultiByteToWideChar(CP_ACP, 0, cmd, -1, wtmp2.data(), static_cast<int>(wtmp2.size()));
        wcslcpytoutf8(tmp2.data(), wtmp2.data(), tmp2.size() - 1);
        cmdname = tmp2.c_str();
    } else {
        if (remotedir)
            dirname = remotedir;
        cmdname = cmd;
    }

    // Replace backslashes with slashes
    std::replace(dirname.begin(), dirname.end(), '\\', '/');

    std::string display = "Quote: ";
    display += cmd;
    std::replace(display.begin(), display.end(), '\\', '/');
    ShowStatus(display.c_str());
    SFTP_LOG("SHELL", "Quote command: %zu bytes", strlen(cmd));

    // Build command: cd <dir> && <cmd> (if dir given)
    std::string fullCmd;
    if (remotedir) {
        fullCmd = "cd '";
        fullCmd += string_util::ShellQuoteSingle(dirname) + "' && ";
    }
    fullCmd += cmdname;

    if (cs->shell_transfer_force)
        return QuoteOnPersistentShell(cs, fullCmd, reply, replylen, false);

    auto channel = ConnectChannel(cs->session.get(), cs->sock);
    if (!channel)
        return -1;

    if (!SendExecCommand(cs, channel, fullCmd.c_str(), true)) {
        return -1;
    }

    std::string errbuf;
    std::string msgbuf;
    std::array<char, 4096> linebuf{};

    while (ReadChannelLine(channel.get(), linebuf.data(), linebuf.size() - 1,
                           msgbuf, errbuf, cs->sock,
                           idleTimeoutMs, totalTimeoutMs))
    {
        StripEscapeSequences(linebuf.data());
        if (!reply) {
            ShowStatus(linebuf.data());
        } else {
            if (reply[0])
                strlcat(reply, "\r\n", replylen);
            strlcat(reply, linebuf.data(), replylen);
        }
    }

    // The loop also ends on its timeouts. A command that never finished has
    // no exit status, and the channel reports 0 for one that never came —
    // which would pass a hung `mv` or `cp` for a success. The status arrives
    // after the output ends and before the channel closes.
    if (!channel->eof()) {
        SFTP_LOG("SHELL", "Quote command timed out before it finished");
        return -1;
    }
    if (WaitForOperation([&] { return channel->waitClosed(); }, kShellCloseTimeoutMs, cs) != 0) {
        SFTP_LOG("SHELL", "Quote command: no exit status");
        return -1;
    }

    const int rc = channel->getExitStatus();
    SFTP_LOG("SHELL", "Quote command done: rc=%d", rc);
    if (rc != 0) {
        char tmp[128];
        snprintf(tmp, sizeof(tmp), "Function return code: %d", rc);
        ShowStatus(tmp);
        if (!errbuf.empty()) {
            std::string err = errbuf;
            StripEscapeSequences(err.data());
            if (err.substr(0, 19) == "stdin: is not a tty")
                err = err.substr(19);
            ShowStatus(err.c_str());
            if (reply) {
                if (reply[0])
                    strlcat(reply, "\r\n", replylen);
                strlcat(reply, err.c_str(), replylen);
            }
        }
    }

    return rc >= 0 ? rc : 1;
}

int SftpQuoteCommand2W(pConnectSettings cs, LPCWSTR remotedir, LPCWSTR cmd,
                       char* reply, size_t replylen)
{
    if (reply && replylen > 0)
        reply[0] = '\0';

    if (!cs)
        return -1;

    // Converted strictly: a character the session's codepage lacks would
    // otherwise become a look-alike, a fullwidth apostrophe a real quote in
    // the middle of the command.
    std::string dirname, cmdname;
    {
        std::string tmp(wdirtypemax, '\0');
        if (remotedir) {
            if (!CopyRemotePathW2A(cs, remotedir, tmp.data(), tmp.size()))
                return -1;
            dirname = tmp.c_str();
        }
        if (!CopyStringW2A(cs, cmd, tmp.data(), tmp.size()))
            return -1;
        cmdname = tmp.c_str();
    }

    std::wstring display = L"Quote: ";
    display += cmd;
    std::replace(display.begin(), display.end(), L'\\', L'/');
    ShowStatusW(display.c_str());

    std::string fullCmd;
    if (remotedir) {
        fullCmd = "cd '";
        fullCmd += string_util::ShellQuoteSingle(dirname) + "' && ";
    }
    fullCmd += cmdname;

    if (cs->shell_transfer_force)
        return QuoteOnPersistentShell(cs, fullCmd, reply, replylen, true);

    auto channel = ConnectChannel(cs->session.get(), cs->sock);
    if (!channel)
        return -1;

    if (!SendExecCommand(cs, channel, fullCmd.c_str(), true)) {
        return -1;
    }

    std::string errbuf;
    std::string msgbuf;
    std::array<char, 4096> linebuf{};
    const auto start = std::chrono::steady_clock::now();
    int loop = 0;
    auto lasttime = get_sys_ticks();

    // A command may run long without a word — a `cp` of a large file. It is
    // waited for in short steps for as long as its channel is open, with
    // Total Commander's progress dialog to cancel it from.
    while (true) {
        if (ReadChannelLine(channel.get(), linebuf.data(), linebuf.size() - 1,
                            msgbuf, errbuf, cs->sock, 2000, 2000)) {
            StripEscapeSequences(linebuf.data());
            if (!reply) {
                std::array<wchar_t, 4096> wline{};
                CopyStringA2W(cs, linebuf.data(), wline.data(), wline.size() - 1, false);
                ShowStatusW(wline.data());
            } else {
                if (reply[0])
                    strlcat(reply, "\r\n", replylen);
                strlcat(reply, linebuf.data(), replylen);
            }
        } else if (channel->eof() || IsSocketError(cs->sock)) {
            break;
        }
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        if (elapsed > kQuoteProgressStartMs && ProgressLoop("QUOTE", 0, 100, &loop, &lasttime))
            break;
    }

    // A command that never finished has no exit status, and the channel
    // reports 0 for one that never came — which would pass a cancelled `mv`
    // or `cp` for a success. The status arrives after the output ends and
    // before the channel closes.
    if (!channel->eof()) {
        SFTP_LOG("SHELL", "Quote command cancelled before it finished");
        return -1;
    }
    if (WaitForOperation([&] { return channel->waitClosed(); }, kShellCloseTimeoutMs, cs) != 0) {
        SFTP_LOG("SHELL", "Quote command: no exit status");
        return -1;
    }

    const int rc = channel->getExitStatus();
    SFTP_LOG("SHELL", "Quote command done: rc=%d", rc);
    if (rc != 0) {
        char tmp[128];
        snprintf(tmp, sizeof(tmp), "Function return code: %d", rc);
        ShowStatus(tmp);
        if (!errbuf.empty()) {
            std::string err = errbuf;
            StripEscapeSequences(err.data());
            if (err.substr(0, 19) == "stdin: is not a tty")
                err = err.substr(19);
            ShowStatus(err.c_str());
            if (reply) {
                if (reply[0])
                    strlcat(reply, "\r\n", replylen);
                strlcat(reply, err.c_str(), replylen);
            }
        }
    }

    return rc >= 0 ? rc : 1;
}