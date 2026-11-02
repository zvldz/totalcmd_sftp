#include "global.h"
#include <windows.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <array>
#include <memory>
#include <chrono>
#include "SftpClient.h"
#include "PluginEntryPoints.h"
#include "fsplugin.h"
#include "ServerRegistry.h"
#include "res/resource.h"
#include "CoreUtils.h"
#include "UtfConversion.h"
#include "UnicodeHelpers.h"
#include "FtpDirectoryParser.h"
#include "SftpInternal.h"
#include "PhpAgentClient.h"

namespace {

constexpr const char* kScpListBeginMarker = "__WFX_LIST_BEGIN__";
constexpr const char* kScpListEndMarker = "__WFX_LIST_END__";
constexpr uint32_t kScpDataMagic = 0x53435044u; // 'SCPD'
constexpr int kScpWriteTimeoutMs = 15000;
constexpr int kScpReadTimeoutMs = 30000;
constexpr int kScpDeleteReadTimeoutMs = 15000;
constexpr int kSftpProgressStartMs = 2000;
constexpr int kSftpAbortGraceMs = 2000;
constexpr int kSftpProgressDivMs = 200;

struct ScpListState {
    std::vector<WIN32_FIND_DATAW> entries;
    size_t nextIndex = 0;
};

struct ScpData {
    uint32_t magic;
    std::unique_ptr<ISshChannel> channel;
    std::array<char, 2048> msgbuf;
    std::array<char, 2048> errbuf;
    std::unique_ptr<ScpListState> listingState;
};

ScpData* AsScpData(LPVOID data) noexcept
{
    if (!data) return nullptr;
    ScpData* scpd = static_cast<ScpData*>(data);
    return (scpd->magic == kScpDataMagic) ? scpd : nullptr;
}

// Full st_mode from the `drwxr-xr-x` column: file type plus permission bits,
// with s/S and t/T as setuid/setgid/sticky (upper case: execute not set).
DWORD ParseLsMode(const std::string& perms)
{
    if (perms.size() < 10)
        return 0;
    DWORD mode = 0;
    switch (perms[0]) {
        case 'd': mode = LIBSSH2_SFTP_S_IFDIR;  break;
        case 'l': mode = LIBSSH2_SFTP_S_IFLNK;  break;
        case 'b': mode = LIBSSH2_SFTP_S_IFBLK;  break;
        case 'c': mode = LIBSSH2_SFTP_S_IFCHR;  break;
        case 'p': mode = LIBSSH2_SFTP_S_IFIFO;  break;
        case 's': mode = LIBSSH2_SFTP_S_IFSOCK; break;
        default:  mode = LIBSSH2_SFTP_S_IFREG;  break;
    }
    static constexpr DWORD kBits[9] = { 0400, 0200, 0100, 040, 020, 010, 04, 02, 01 };
    for (int i = 0; i < 9; ++i) {
        const char c = perms[1 + i];
        if (c != '-' && c != 'S' && c != 'T')
            mode |= kBits[i];
    }
    if (perms[3] == 's' || perms[3] == 'S') mode |= 04000;
    if (perms[6] == 's' || perms[6] == 'S') mode |= 02000;
    if (perms[9] == 't' || perms[9] == 'T') mode |= 01000;
    return mode;
}

// Date columns of `ls -la` run with LC_TIME=C and TZ=UTC0: "Mon DD HH:MM" for
// recent files, "Mon DD YYYY" for older ones. A time without a year that
// lands more than a day ahead belongs to last year.
bool ParseLsDate(const std::string& mon, const std::string& day,
                 const std::string& timeOrYear, FILETIME& ft)
{
    static constexpr const char* kMonths[12] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    WORD month = 0;
    for (WORD i = 0; i < 12; ++i) {
        if (_stricmp(mon.c_str(), kMonths[i]) == 0) {
            month = i + 1;
            break;
        }
    }
    const int d = atoi(day.c_str());
    if (month == 0 || d < 1 || d > 31)
        return false;

    SYSTEMTIME st{};
    st.wMonth = month;
    st.wDay   = static_cast<WORD>(d);
    int hh = 0, mm = 0;
    if (sscanf_s(timeOrYear.c_str(), "%d:%d", &hh, &mm) == 2) {
        if (hh < 0 || hh > 23 || mm < 0 || mm > 59)
            return false;
        SYSTEMTIME now{};
        GetSystemTime(&now);
        st.wYear   = now.wYear;
        st.wHour   = static_cast<WORD>(hh);
        st.wMinute = static_cast<WORD>(mm);
        FILETIME nowFt{};
        SystemTimeToFileTime(&now, &nowFt);
        auto ticks = [](const FILETIME& f) {
            return (static_cast<ULONGLONG>(f.dwHighDateTime) << 32) | f.dwLowDateTime;
        };
        constexpr ULONGLONG kOneDay100ns = 24ULL * 60 * 60 * 10000000;
        if (SystemTimeToFileTime(&st, &ft) && ticks(ft) > ticks(nowFt) + kOneDay100ns)
            --st.wYear;
    } else {
        const int year = atoi(timeOrYear.c_str());
        if (year < 1601 || year > 9999)
            return false;
        st.wYear = static_cast<WORD>(year);
    }
    return SystemTimeToFileTime(&st, &ft) != 0;
}

// Owner, group and link target from an `ls -l` style line, the shape of both
// the SCP listing and SFTP's long entry. The link count has to be a number,
// or the line is not in that shape and nothing is taken from it.
void ExtrasFromLsLine(pConnectSettings cs, const char* line, ListingExtra& extra)
{
    std::vector<std::string_view> tokens;
    const std::string_view sv(line);
    size_t pos = 0;
    while (tokens.size() < 4 && pos < sv.size()) {
        pos = sv.find_first_not_of(" \t", pos);
        if (pos == std::string_view::npos)
            break;
        const size_t end = (std::min)(sv.find_first_of(" \t", pos), sv.size());
        tokens.push_back(sv.substr(pos, end - pos));
        pos = end;
    }
    if (tokens.size() < 4 ||
        tokens[1].find_first_not_of("0123456789") != std::string_view::npos)
        return;

    auto widen = [cs](std::string_view s) {
        const std::string narrow(s);
        std::array<WCHAR, 1024> wide{};
        CopyStringA2W(cs, narrow.c_str(), wide.data(), wide.size());
        return std::wstring(wide.data());
    };
    extra.owner = widen(tokens[2]);
    extra.group = widen(tokens[3]);

    if (tokens[0].starts_with('l')) {
        const size_t arrow = sv.find(" -> ");
        if (arrow != std::string_view::npos) {
            std::string_view target = sv.substr(arrow + 4);
            while (!target.empty() && (target.back() == '\r' || target.back() == '\n'))
                target.remove_suffix(1);
            extra.linkTarget = widen(target);
        }
    }
}

// Parse SCP listing line into WIN32_FIND_DATAW
bool ParseScpListingLine(pConnectSettings cs, const char* line, WIN32_FIND_DATAW& outData,
                         ListingExtra* extra = nullptr)
{
    if (!cs || !line || !line[0])
        return false;

    // Work on a copy
    std::string lineStr(line);
    // Trim leading spaces
    size_t start = lineStr.find_first_not_of(" \t");
    if (start == std::string::npos)
        return false;
    lineStr = lineStr.substr(start);
    if (lineStr.empty())
        return false;

    const char c0 = lineStr[0];
    if (!(c0 == '-' || c0 == 'd' || c0 == 'l' || c0 == 'b' || c0 == 'c' || c0 == 'p' || c0 == 's'))
        return false;

    // Tokenize by spaces
    std::vector<std::string> tokens;
    size_t pos = 0;
    while (pos < lineStr.size()) {
        while (pos < lineStr.size() && (lineStr[pos] == ' ' || lineStr[pos] == '\t'))
            ++pos;
        if (pos >= lineStr.size())
            break;
        size_t tokStart = pos;
        while (pos < lineStr.size() && lineStr[pos] != ' ' && lineStr[pos] != '\t')
            ++pos;
        tokens.push_back(lineStr.substr(tokStart, pos - tokStart));
    }

    if (tokens.size() < 9)
        return false;

    // Find name start: after 8 tokens
    size_t namePos = 0;
    int tokCount = 0;
    pos = 0;
    while (tokCount < 8 && pos < lineStr.size()) {
        while (pos < lineStr.size() && (lineStr[pos] == ' ' || lineStr[pos] == '\t'))
            ++pos;
        if (pos >= lineStr.size())
            break;
        while (pos < lineStr.size() && lineStr[pos] != ' ' && lineStr[pos] != '\t')
            ++pos;
        ++tokCount;
    }
    while (pos < lineStr.size() && (lineStr[pos] == ' ' || lineStr[pos] == '\t'))
        ++pos;
    if (pos >= lineStr.size())
        return false;
    std::string name = lineStr.substr(pos);
    // Trim trailing whitespace
    while (!name.empty() && (name.back() == ' ' || name.back() == '\t' || name.back() == '\r' || name.back() == '\n'))
        name.pop_back();
    // Remove symlink arrow
    size_t arrow = name.find(" -> ");
    if (arrow != std::string::npos)
        name.resize(arrow);
    if (name.empty())
        return false;

    WIN32_FIND_DATAW fd{};
    CopyStringA2W(cs, name.c_str(), fd.cFileName, _countof(fd.cFileName));
    if (!fd.cFileName[0])
        return false;

    fd.dwFileAttributes = (c0 == 'd') ? FILE_ATTRIBUTE_DIRECTORY : 0;
    if (const DWORD mode = ParseLsMode(tokens[0])) {
        fd.dwFileAttributes |= FS_ATTR_UNIXMODE;
        fd.dwReserved0 = mode;
    }
    // A date that does not parse leaves the field empty; the entry stays.
    ParseLsDate(tokens[5], tokens[6], tokens[7], fd.ftLastWriteTime);

    if (c0 != 'd' && c0 != 'l' && tokens.size() > 4) {
        unsigned long long sz = _strtoui64(tokens[4].c_str(), nullptr, 10);
        fd.nFileSizeHigh = static_cast<DWORD>(sz >> 32);
        fd.nFileSizeLow = static_cast<DWORD>(sz & 0xFFFFFFFFULL);
    }

    if (extra) {
        extra->mode = (fd.dwFileAttributes & FS_ATTR_UNIXMODE) ? fd.dwReserved0 : 0;
        ExtrasFromLsLine(cs, lineStr.c_str(), *extra);
    }

    outData = fd;
    return true;
}

} // anonymous namespace

int SftpFindFirstFileW(pConnectSettings cs, LPCWSTR remotedir, LPVOID* davdataptr)
{
    {
        std::array<char, wdirtypemax> statusBuf{};
        LoadStr(statusBuf, IDS_GET_DIR);
        size_t len = strlen(statusBuf.data());
        if (len < statusBuf.size() - 1)
            walcopy(statusBuf.data() + len, remotedir, static_cast<int>(statusBuf.size() - len - 1));
        // Normalise '\' (TC's API convention) to '/' (SSH/SFTP native) so
        // status lines for directory listings match the slash style used by
        // ShowTransferStart for Upload/Download messages.
        std::replace(statusBuf.begin(), statusBuf.end(), '\\', '/');
        ShowStatus(statusBuf.data());
    }

    for (int i = 0; i < 10; ++i) {
        if (EscapePressed())
            Sleep(100);
    }

    std::string dirStr(wdirtypemax, '\0');
    CopyStringW2A(cs, remotedir, dirStr.data(), dirStr.size());
    dirStr.resize(strlen(dirStr.c_str()));
    std::replace(dirStr.begin(), dirStr.end(), '\\', '/');
    if (dirStr.size() > 1 && dirStr.back() != '/')
        dirStr += '/';

    if (IsPhpAgentTransport(cs)) {
        std::vector<WIN32_FIND_DATAW> entries;
        int rc = PhpAgentListDirectoryW(cs, remotedir, entries);
        if (rc != SFTP_OK)
            return rc;

        auto scpd = std::make_unique<ScpData>();
        scpd->magic = kScpDataMagic;
        auto state = std::make_unique<ScpListState>();
        state->entries = std::move(entries);
        scpd->listingState = std::move(state);
        *davdataptr = scpd.release();
        wcslcpy(cs->lastactivepath, remotedir, _countof(cs->lastactivepath) - 1);
        return SFTP_OK;
    }

    if (cs->scponly) {
        // Retry loop in case of silent TCP disconnections (e.g., home.pl)
        for (int attempt = 0; attempt < 2; ++attempt) {
            if (!EnsureScpShell(cs)) {
                bool sockLost = (cs->sock == INVALID_SOCKET) || IsSocketError(cs->sock);
                int sessErr = cs->session ? cs->session->lastErrno() : -1;
                if (sockLost || sessErr == LIBSSH2_ERROR_SOCKET_DISCONNECT ||
                    sessErr == LIBSSH2_ERROR_SOCKET_SEND || sessErr == LIBSSH2_ERROR_SOCKET_RECV) {
                    ShowStatusId(IDS_LOG_SCP_SESSION_LOST, nullptr, true);
                    SftpCloseConnection(cs);
                    Sleep(RECONNECT_SLEEP_MS);
                    if (SftpConnect(cs) != SFTP_OK || !EnsureScpShell(cs)) {
                        if (attempt == 1) { // If this is your second attempt, give up
                            ShowStatusId(IDS_LOG_SCP_NO_SHELL, nullptr, true);
                            return SFTP_FAILED;
                        }
                        continue; // Try again
                    }
                } else {
                    ShowStatusId(IDS_LOG_SCP_NO_SHELL, nullptr, true);
                    return SFTP_FAILED;
                }
            }

            ISshChannel* channel = cs->scpShellChannel.get();
            if (!channel) {
                ShowStatusId(IDS_LOG_SCP_NO_SHELL, nullptr, true);
                return SFTP_FAILED;
            }

            cs->scpShellMsgBuf.clear();
            cs->scpShellErrBuf.clear();

            // The path goes to the shell exactly as it is.
            const std::string& listTarget = dirStr;

            static unsigned scpListSeq = 1;
            const unsigned markerSeq = scpListSeq++;
            std::string beginMarker  = std::string(kScpListBeginMarker) + "_" + std::to_string(markerSeq);
            std::string endMarker    = std::string(kScpListEndMarker)   + "_" + std::to_string(markerSeq);
            // `ls` appends its exit status to the end marker, which the reader
            // hands back. Everything stays on one line on purpose: the shell
            // echoes the command back, and an echo long enough to wrap arrives
            // as two lines, the second of which would look like the end marker
            // and cut the reading short before any output was seen.
            // `env` sets the locale and zone in any shell, csh included, and
            // runs the real `ls` past any alias: English month names, times
            // in UTC.
            std::string command = "echo \"" + beginMarker + "\"; env TZ=UTC0 LC_TIME=C ls -la '" +
                                  string_util::ShellQuoteSingle(listTarget) +
                                  "'; echo \"" + endMarker + "\":$?\n";
            SFTP_LOG("FIND", "SCP listing '%s'", listTarget.c_str());

            // Write command
            bool writeFailed = false;
            {
                const auto writeStart = std::chrono::steady_clock::now();
                size_t written = 0;
                while (written < command.size()) {
                    int rc = static_cast<int>(channel->write(command.data() + written, command.size() - written));
                    if (rc > 0) {
                        written += rc;
                        continue;
                    }
                    if (rc != LIBSSH2_ERROR_EAGAIN) {
                        writeFailed = true;
                        break;
                    }
                    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - writeStart).count();
                    if (elapsed > kScpWriteTimeoutMs) {
                        writeFailed = true;
                        break;
                    }
                    IsSocketReadable(cs->sock);
                }
            }

            // Instead of immediately throwing an error, we force a restart on the next iteration.
            if (writeFailed) {
                // Close the dead channel; on the next iteration EnsureScpShell will
                // re-open it (or detect a broken socket via IsSocketError and reconnect).
                // Do NOT touch cs->sock here — it is shared by the whole session.
                CloseScpShell(cs);
                if (attempt == 0)
                    continue;
                return SFTP_FAILED;
            }

            std::vector<std::string> lines;
            std::string endLine;
            bool gotEnd = ScpReadCommandOutput(cs, endMarker.c_str(), lines, kScpReadTimeoutMs,
                                               beginMarker.c_str(), &endLine);
            int listStatus = 0;
            {
                const size_t colon = endLine.rfind(':');
                if (colon != std::string::npos)
                    listStatus = atoi(endLine.c_str() + colon + 1);
            }

            std::vector<WIN32_FIND_DATAW> entries;
            DirectoryExtras extras;
            for (const auto& line : lines) {
                if (line.empty() || _strnicmp(line.c_str(), "total ", 6) == 0)
                    continue;
                WIN32_FIND_DATAW fd{};
                ListingExtra extra;
                if (ParseScpListingLine(cs, line.c_str(), fd, &extra)) {
                    if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
                        continue;
                    extras[fd.cFileName] = std::move(extra);
                    entries.push_back(fd);
                }
            }

            SFTP_LOG("FIND", "SCP listing result: status=%d gotEnd=%d rawLines=%d entries=%d first='%s'",
                     listStatus, gotEnd ? 1 : 0, (int)lines.size(), (int)entries.size(),
                     lines.empty() ? "" : lines[0].c_str());

			if (!gotEnd && entries.empty()) {
                if (!cs->scpShellErrBuf.empty()) {
                    std::string err = cs->scpShellErrBuf;
                    StripEscapeSequences(err.data());
                    ShowStatus(err.c_str());
                } else {
                    ShowStatusId(IDS_LOG_SCP_LIST_FAIL, nullptr, true);
                }
                CloseScpShell(cs);

                // Instead of immediately throwing an error, try reconnecting channel.
                if (attempt == 0) {
                    // FIX CLAUDE: Nie niszczymy gniazda TCP! Wystarczy, że CloseScpShell 
                    // zamknęło kanał. W kolejnym cyklu EnsureScpShell otworzy nowy.
                    // cs->sock = INVALID_SOCKET; <-- USUNIĘTE
                    continue;
                }
                return SFTP_FAILED;
            }

            // `ls` reports trouble it ran into while still printing whatever it
            // could read, so a non-zero status is only fatal when it left us
            // with nothing: otherwise the panel would lose a directory it can
            // in fact show. An empty result with a complaint is the case that
            // used to look like an empty directory.
            if (listStatus != 0 && entries.empty()) {
                if (!cs->scpShellErrBuf.empty()) {
                    std::string err = cs->scpShellErrBuf;
                    StripEscapeSequences(err.data());
                    ShowStatus(err.c_str());
                } else {
                    ShowStatusId(IDS_LOG_SCP_LIST_FAIL, nullptr, true);
                }
                return SFTP_FAILED;
            }

            auto scpd = std::make_unique<ScpData>();
            scpd->magic = kScpDataMagic;
            auto state = std::make_unique<ScpListState>();
            state->entries = std::move(entries);
            scpd->listingState = std::move(state);
            *davdataptr = scpd.release();
            wcslcpy(cs->lastactivepath, remotedir, _countof(cs->lastactivepath) - 1);
            cs->listingExtras[ListingDirKey(remotedir)] = std::move(extras);

            return SFTP_OK;
        }
    }

    if (!ReconnectSFTPChannelIfNeeded(cs))
        return SFTP_FAILED;

    SFTP_LOG("FIND", "SftpFindFirstFileW openDir loop start dir='%s'", dirStr.c_str());
    cs->findstarttime = get_sys_ticks();
    SYSTICKS aborttime = -1;
    int retrycount = 3;
    int loopIter = 0;
    std::unique_ptr<ISftpHandle> dirhandle;

    do {
        ++loopIter;
        dirhandle = cs->sftpsession->openDir(dirStr.c_str());
        if (dirhandle) {
            SFTP_LOG("FIND", "SftpFindFirstFileW openDir OK after %d iters elapsed=%ums",
                     loopIter, (unsigned)get_ticks_between(cs->findstarttime));
            break;
        }

        int err = cs->session->lastErrno();
        if (err != LIBSSH2_ERROR_EAGAIN) {
            if (err == LIBSSH2_FX_EOF || err == LIBSSH2_FX_FAILURE ||
                err == LIBSSH2_FX_BAD_MESSAGE || err == LIBSSH2_FX_NO_CONNECTION ||
                err == LIBSSH2_FX_CONNECTION_LOST || err < 0) {
                --retrycount;
                if (retrycount <= 0)
                    break;
                cs->neednewchannel = true;
                if (!ReconnectSFTPChannelIfNeeded(cs))
                    return SFTP_FAILED;
            }
        } else {
            WaitForSshIo(cs);
        }

        int delta = get_ticks_between(cs->findstarttime);
        if (delta > kSftpProgressStartMs && aborttime == -1) {
            if (ProgressProc(PluginNumber, dirStr.c_str(), "temp", (delta / kSftpProgressDivMs) % 100))
                aborttime = get_sys_ticks() + kSftpAbortGraceMs;
        }
        // Periodic progress log so we see whether the loop is actually spinning
        // (and where it gets stuck if the host process hard-terminates us).
        if ((loopIter % 20) == 0)
            SFTP_LOG("FIND", "  openDir loop iter=%d elapsed=%dms retrycount=%d",
                     loopIter, delta, retrycount);
        delta = get_ticks_between(aborttime);
        if (aborttime != -1 && delta > 0) {
            cs->neednewchannel = true;
            SFTP_LOG("FIND", "SftpFindFirstFileW openDir aborted by user/timeout iter=%d", loopIter);
            break;
        }
    } while (!dirhandle);

    if (!dirhandle) {
        char* errmsg = nullptr;
        int errmsg_len = 0;
        cs->session->lastError(&errmsg, &errmsg_len, false);
        std::string msg = "Directory not opened: ";
        if (errmsg) msg += errmsg;
        ShowStatus(msg.c_str());
        return SFTP_FAILED;
    }

    *davdataptr = dirhandle.release();
    wcslcpy(cs->lastactivepath, remotedir, _countof(cs->lastactivepath) - 1);
    // Refilled entry by entry as SftpFindNextFileW reads the directory.
    cs->listingExtras[ListingDirKey(remotedir)].clear();
    return SFTP_OK;
}

int SftpFindNextFileW(pConnectSettings cs, LPVOID davdataptr, LPWIN32_FIND_DATAW FindData) noexcept
{
    ScpData* scpd = AsScpData(davdataptr);
    if (scpd && scpd->listingState) {
        if (scpd->listingState->nextIndex >= scpd->listingState->entries.size())
            return SFTP_FAILED;
        *FindData = scpd->listingState->entries[scpd->listingState->nextIndex++];
        return SFTP_OK;
    }

    ISftpHandle* dirhandle = static_cast<ISftpHandle*>(davdataptr);
    if (!dirhandle)
        return SFTP_FAILED;

    std::array<char, 512> name{};
    std::array<char, 2048> longentry{};
    LIBSSH2_SFTP_ATTRIBUTES file{};
    SYSTICKS aborttime = -1;

    int rc;
    while ((rc = dirhandle->readdir(name.data(), name.size(),
                                     longentry.data(), longentry.size(), &file)) == LIBSSH2_ERROR_EAGAIN) {
        int delta = get_ticks_between(cs->findstarttime);
        if (delta > kSftpProgressStartMs && aborttime == -1) {
            if (ProgressProc(PluginNumber, "dir", "temp", (delta / kSftpProgressDivMs) % 100))
                aborttime = get_sys_ticks() + kSftpAbortGraceMs;
        }
        delta = get_ticks_between(aborttime);
        if (aborttime != -1 && delta > 0) {
            cs->neednewchannel = true;
            break;
        }
        IsSocketReadable(cs->sock);
    }

    if (rc > 0) {
        if (cs->detailedlog && longentry[0])
            ShowStatus(longentry.data());

        FindData->dwFileAttributes = 0;
        CopyStringA2W(cs, name.data(), FindData->cFileName, _countof(FindData->cFileName));
        if (file.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) {
            if ((file.permissions & S_IFMT) == S_IFDIR)
                FindData->dwFileAttributes = FILE_ATTRIBUTE_DIRECTORY;
        } else if (longentry[0] == 'd') {
            FindData->dwFileAttributes = FILE_ATTRIBUTE_DIRECTORY;
        }

        FindData->cAlternateFileName[0] = 0;
        FindData->ftCreationTime.dwHighDateTime = 0;
        FindData->ftCreationTime.dwLowDateTime = 0;
        FindData->ftLastAccessTime.dwHighDateTime = 0;
        FindData->ftLastAccessTime.dwLowDateTime = 0;

        // A link's size is the length of its target path; left out, as in SCP
        // mode, so the panel shows it as a link.
        const bool isLink = (file.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) &&
                            (file.permissions & LIBSSH2_SFTP_S_IFMT) == LIBSSH2_SFTP_S_IFLNK;
        if (file.flags & LIBSSH2_SFTP_ATTR_SIZE && FindData->dwFileAttributes == 0 && !isLink) {
            FindData->nFileSizeHigh = static_cast<DWORD>(file.filesize >> 32);
            FindData->nFileSizeLow = static_cast<DWORD>(file.filesize);
        } else {
            FindData->nFileSizeHigh = 0;
            FindData->nFileSizeLow = 0;
        }

        if (file.flags & LIBSSH2_SFTP_ATTR_ACMODTIME) {
            ConvUnixTimeToFileTime(&FindData->ftLastWriteTime, file.mtime);
        }

        if (file.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) {
            FindData->dwFileAttributes |= 0x80000000;
            FindData->dwReserved0 = file.permissions & 0xFFFF;
        }

        // The long entry carries the names; a server that sends none still
        // has the numeric ids in the attributes.
        ListingExtra extra;
        extra.mode = (file.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) ? (file.permissions & 0xFFFF) : 0;
        if (longentry[0])
            ExtrasFromLsLine(cs, longentry.data(), extra);
        if (extra.owner.empty() && (file.flags & LIBSSH2_SFTP_ATTR_UIDGID)) {
            extra.owner = std::to_wstring(file.uid);
            extra.group = std::to_wstring(file.gid);
        }
        cs->listingExtras[ListingDirKey(cs->lastactivepath)][FindData->cFileName] = std::move(extra);
        return SFTP_OK;
    }
    return SFTP_FAILED;
}

std::wstring ListingDirKey(std::wstring_view dir)
{
    std::wstring key(dir);
    std::replace(key.begin(), key.end(), L'/', L'\\');
    while (key.size() > 1 && key.back() == L'\\')
        key.pop_back();
    if (key.empty())
        key = L"\\";
    return key;
}

const ListingExtra* FindListingExtra(pConnectSettings cs, std::wstring_view relPath)
{
    if (!cs)
        return nullptr;
    const size_t sep = relPath.find_last_of(L"\\/");
    if (sep == std::wstring_view::npos)
        return nullptr;
    const auto dir = cs->listingExtras.find(ListingDirKey(relPath.substr(0, sep)));
    if (dir == cs->listingExtras.end())
        return nullptr;
    const auto it = dir->second.find(std::wstring(relPath.substr(sep + 1)));
    return it == dir->second.end() ? nullptr : &it->second;
}

int SftpFindClose(pConnectSettings cs, LPVOID davdataptr)
{
    ScpData* scpd = AsScpData(davdataptr);
    if (scpd) {
        delete scpd;
        return SFTP_OK;
    }

    ISftpHandle* dirhandle = static_cast<ISftpHandle*>(davdataptr);
    if (!dirhandle)
        return SFTP_FAILED;

    if (!cs) {
        delete dirhandle;
        return SFTP_OK;
    }

    SYSTICKS aborttime = -1;
    while (dirhandle->close() == LIBSSH2_ERROR_EAGAIN) {
        int delta = get_ticks_between(cs->findstarttime);
        if (delta > kSftpProgressStartMs && aborttime == -1) {
            if (ProgressProc(PluginNumber, "close dir", "temp", (delta / kSftpProgressDivMs) % 100))
                aborttime = get_sys_ticks() + kSftpAbortGraceMs;
        }
        delta = get_ticks_between(aborttime);
        if (aborttime != -1 && delta > 0) {
            cs->neednewchannel = true;
            break;
        }
        IsSocketReadable(cs->sock);
    }
    delete dirhandle;
    return SFTP_OK;
}

int SftpCreateDirectoryW(pConnectSettings cs, LPCWSTR Path)
{
    std::array<char, MAX_PATH> msgBuf{};
    LoadStr(msgBuf, IDS_MK_DIR);
    std::wstring display(wdirtypemax, L'\0');
    awlcopy(display.data(), msgBuf.data(), wdirtypemax - 1);
    display.resize(wcslen(display.c_str()));
    display += Path;
    ShowStatusW(display.c_str());

    std::string dirStr(wdirtypemax, '\0');
    CopyStringW2A(cs, Path, dirStr.data(), dirStr.size());
    dirStr.resize(strlen(dirStr.c_str()));
    std::replace(dirStr.begin(), dirStr.end(), '\\', '/');

    if (IsPhpAgentTransport(cs))
        return PhpAgentCreateDirectoryW(cs, Path);

    if (cs->scponly) {
        auto channel = ConnectChannel(cs->session.get(), cs->sock);
        if (channel) {
            const std::string cmd = "mkdir '" + string_util::ShellQuoteSingle(dirStr) + "'";
            if (GetChannelCommandReply(cs->session.get(), channel.get(), cmd.c_str(), cs->sock))
                return SFTP_OK;
        }
        ShowStatusId(IDS_LOG_SCP_MKDIR_FAIL, nullptr, true);
        return SFTP_FAILED;
    }

    const SYSTICKS start = get_sys_ticks();
    SYSTICKS aborttime = -1;
    int rc;
    do {
        rc = cs->sftpsession->mkdir(dirStr.c_str(), cs->dirmod);
        if (rc == 0)
            break;
        int delta = get_ticks_between(cs->findstarttime);
        if (delta > kSftpProgressStartMs && aborttime == -1) {
            if (EscapePressed())
                aborttime = get_sys_ticks() + kSftpAbortGraceMs;
        }
        delta = get_ticks_between(aborttime);
        if (aborttime != -1 && delta > 0) {
            cs->neednewchannel = true;
            break;
        }
        if (rc == LIBSSH2_ERROR_EAGAIN)
            WaitForSshIo(cs);
    } while (rc == LIBSSH2_ERROR_EAGAIN);

    if (rc == 0) {
        if (cs->dirmod != 0755) {
            LIBSSH2_SFTP_ATTRIBUTES attr{};
            attr.flags = LIBSSH2_SFTP_ATTR_PERMISSIONS;
            attr.permissions = cs->dirmod;
            do {
                rc = cs->sftpsession->setstat(dirStr.c_str(), &attr);
                if (EscapePressed()) {
                    cs->neednewchannel = true;
                    break;
                }
                if (rc == LIBSSH2_ERROR_EAGAIN)
                    IsSocketReadable(cs->sock);
            } while (rc == LIBSSH2_ERROR_EAGAIN);
        }
        return SFTP_OK;
    } else {
        char* errmsg = nullptr;
        int errmsg_len = 0;
        cs->session->lastError(&errmsg, &errmsg_len, false);
        std::string msg = "Directory not created: ";
        if (errmsg) msg += errmsg;
        ShowStatus(msg.c_str());
        return SFTP_FAILED;
    }
}

int SftpDeleteFileW(pConnectSettings cs, LPCWSTR RemoteName, bool isdir)
{
    std::array<char, MAX_PATH> msgBuf{};
    LoadStr(msgBuf, IDS_DELETE);
    std::wstring display(wdirtypemax, L'\0');
    awlcopy(display.data(), msgBuf.data(), wdirtypemax - 1);
    display.resize(wcslen(display.c_str()));
    display += RemoteName;
    ShowStatusW(display.c_str());

    std::string nameStr(wdirtypemax, '\0');
    CopyStringW2A(cs, RemoteName, nameStr.data(), nameStr.size());
    nameStr.resize(strlen(nameStr.c_str()));
    std::replace(nameStr.begin(), nameStr.end(), '\\', '/');

    if (IsPhpAgentTransport(cs))
        return PhpAgentDeleteFileW(cs, RemoteName, isdir);

    // Names that address no single file are refused before any command is
    // built. A shell asked to remove "/" would take the request literally, and
    // a truncated or half-resolved path is exactly how such a name arrives.
    {
        std::string bare = nameStr;
        while (!bare.empty() && (bare.back() == '/' || bare.back() == ' '))
            bare.pop_back();
        if (bare.empty() || bare == "/~" || bare == "." || bare == ".." || bare == "~") {
            SFTP_LOG("SCP", "refusing to delete '%s'", nameStr.c_str());
            return SFTP_FAILED;
        }
    }

    if (cs->scponly) {
        if (!EnsureScpShell(cs))
            return SFTP_FAILED;

        // `rm` says whether it worked through a line of its own. Hanging the
        // status on the end marker cannot work: the reader stops at that marker
        // and drops the line it arrived on, so the status was never read and
        // every deletion reported success.
        auto runDelete = [&](const std::string& target) -> bool {
            static unsigned scpDeleteSeq = 1;
            const unsigned seq = scpDeleteSeq++;
            const std::string beginMarker =
                std::string(kScpListBeginMarker) + "_RM_" + std::to_string(seq);
            const std::string endMarker =
                std::string(kScpListEndMarker) + "_RM_" + std::to_string(seq);

            // The command opens by echoing a marker of its own, exactly as the
            // listing does. Without it the shell's echo of the command line —
            // which carries the end marker and a literal "$?" — is taken for
            // the result, and a deletion reads as successful whether the file
            // went away or not.
            //
            // A directory goes with `rmdir`, which refuses one that is not
            // empty, as SFTP's rmdir does. Total Commander removes the files
            // itself and then asks for the empty directory; after a move it
            // relies on that refusal to keep whatever was skipped or failed.
            std::string cmd = "echo \"" + beginMarker + "\"; ";
            cmd += isdir ? "rmdir '" : "rm -f '";
            cmd += string_util::ShellQuoteSingle(target) + "'";
            cmd += "; echo \"" + endMarker + "\":$?\n";

            ISshChannel* channel = cs->scpShellChannel.get();
            if (!channel)
                return false;

            const auto writeStart = std::chrono::steady_clock::now();
            size_t written = 0;
            while (written < cmd.size()) {
                int rc = static_cast<int>(channel->write(cmd.data() + written, cmd.size() - written));
                if (rc > 0) {
                    written += rc;
                    continue;
                }
                if (rc != LIBSSH2_ERROR_EAGAIN)
                    return false;
                const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - writeStart).count();
                if (elapsed > kScpWriteTimeoutMs)
                    return false;
                IsSocketReadable(cs->sock);
            }

            std::vector<std::string> lines;
            std::string endLine;
            const bool gotEnd = ScpReadCommandOutput(cs, endMarker.c_str(), lines,
                                                     kScpDeleteReadTimeoutMs,
                                                     beginMarker.c_str(), &endLine);
            int exitCode = -1;
            const size_t colon = endLine.rfind(':');
            if (colon != std::string::npos)
                exitCode = atoi(endLine.c_str() + colon + 1);
            return gotEnd && exitCode == 0;
        };

        return runDelete(nameStr) ? SFTP_OK : SFTP_FAILED;
    }

    const SYSTICKS start = get_sys_ticks();
    SYSTICKS aborttime = -1;
    int rc;
    do {
        rc = isdir ? cs->sftpsession->rmdir(nameStr.c_str())
                   : cs->sftpsession->unlink(nameStr.c_str());
        int delta = get_ticks_between(start);
        if (delta > kSftpProgressStartMs && aborttime == -1) {
            if (ProgressProcT(PluginNumber, display.data(), L"delete", (delta / kSftpProgressDivMs) % 100))
                aborttime = get_sys_ticks() + kSftpAbortGraceMs;
        }
        delta = get_ticks_between(aborttime);
        if (aborttime != -1 && delta > 0) {
            cs->neednewchannel = true;
            break;
        }
        if (rc == LIBSSH2_ERROR_EAGAIN)
            IsSocketReadable(cs->sock);
    } while (rc == LIBSSH2_ERROR_EAGAIN);

    if (rc == 0)
        return SFTP_OK;

    char* errmsg = nullptr;
    int errmsg_len = 0;
    cs->session->lastError(&errmsg, &errmsg_len, false);
    std::string err = "Delete FAILED: ";
    if (errmsg) err += errmsg;
    ShowStatus(err.c_str());
    return SFTP_FAILED;
}

int SftpRenameMoveFileW(pConnectSettings cs, LPCWSTR OldName, LPCWSTR NewName, bool Move, bool Overwrite, [[maybe_unused]] bool isdir)
{
    if (!cs)
        return SFTP_FAILED;

    if (IsPhpAgentTransport(cs))
        return PhpAgentRenameMoveFileW(cs, OldName, NewName, Overwrite);

    std::string oldNameA(wdirtypemax, '\0');
    std::string newNameA(wdirtypemax, '\0');
    CopyStringW2A(cs, OldName, oldNameA.data(), oldNameA.size());
    CopyStringW2A(cs, NewName, newNameA.data(), newNameA.size());
    ReplaceBackslashBySlash(oldNameA.data());
    ReplaceBackslashBySlash(newNameA.data());
    oldNameA.resize(strlen(oldNameA.c_str()));
    newNameA.resize(strlen(newNameA.c_str()));

    if (cs->scponly) {
        // Separators are turned around first: the names arrive in Windows form,
        // and a shell reads a backslash inside quotes literally, so the command
        // would name a file that cannot exist. The wide path is what goes to
        // the shell helper — it applies the session's own encoding, which a
        // narrow one would put through the local code page a second time.
        std::wstring oldW(OldName), newW(NewName);
        std::replace(oldW.begin(), oldW.end(), L'\\', L'/');
        std::replace(newW.begin(), newW.end(), L'\\', L'/');

        // The check for an existing destination sits further down, past this
        // branch's return, so a shell-driven move would replace whatever was
        // already there without Total Commander ever asking. `test -e` answers
        // that question here instead.
        // Only `test -e` answering 1 means the name is free; a probe that
        // could not run leaves the question open, and `mv` would replace.
        if (!Overwrite) {
            std::wstring probeW = L"test -e '";
            probeW += string_util::ShellQuoteSingleW(newW.c_str()) + L"'";
            if (SftpQuoteCommand2W(cs, nullptr, probeW.c_str(), nullptr, 0) != 1)
                return SFTP_EXISTS;
        }

        std::wstring cmdW = Move ? L"mv '" : L"cp '";
        cmdW += string_util::ShellQuoteSingleW(oldW.c_str()) + L"' '";
        cmdW += string_util::ShellQuoteSingleW(newW.c_str()) + L"'";

        // The helper returns the command's own exit status, so anything but
        // zero is a failure — treating every non-negative answer as success
        // reported renames that never happened.
        const int rc = SftpQuoteCommand2W(cs, nullptr, cmdW.c_str(), nullptr, 0);
        SFTP_LOG("SCP", "rename: %S -> rc=%d", cmdW.c_str(), rc);
        return (rc == 0) ? SFTP_OK : SFTP_FAILED;
    }

    if (!Overwrite) {
        LIBSSH2_SFTP_ATTRIBUTES attr{};
        int lrc = 0;
        do {
            lrc = cs->sftpsession->lstat(newNameA.data(), &attr);
            if (lrc == LIBSSH2_ERROR_EAGAIN)
                IsSocketReadable(cs->sock);
        } while (lrc == LIBSSH2_ERROR_EAGAIN);
        if (lrc >= 0)
            return SFTP_EXISTS;
    }

    int rc = 0;
    do {
        rc = cs->sftpsession->rename(oldNameA.data(), newNameA.data());
        if (rc == LIBSSH2_ERROR_EAGAIN)
            IsSocketReadable(cs->sock);
    } while (rc == LIBSSH2_ERROR_EAGAIN);
    return (rc == 0) ? SFTP_OK : SFTP_FAILED;
}

int SftpSetAttr(pConnectSettings cs, LPCSTR RemoteName, int NewAttr)
{
    if (!cs || !RemoteName || !RemoteName[0])
        return SFTP_FAILED;
    if (cs->scponly || IsPhpAgentTransport(cs))
        return SFTP_OK;  // no SFTP channel available; silently skip
    if (!cs->sftpsession)
        return SFTP_FAILED;

    std::string nameStr(RemoteName);
    std::replace(nameStr.begin(), nameStr.end(), '\\', '/');

    // Fetch current permissions via lstat so we can do a RMW on the mode bits.
    LIBSSH2_SFTP_ATTRIBUTES attrs{};
    int rc = 0;
    do {
        rc = cs->sftpsession->lstat(nameStr.c_str(), &attrs);
        if (rc == LIBSSH2_ERROR_EAGAIN)
            IsSocketReadable(cs->sock);
    } while (rc == LIBSSH2_ERROR_EAGAIN);

    if (rc != 0 || !(attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS))
        return SFTP_FAILED;

    // Map Windows FILE_ATTRIBUTE_READONLY (0x01) onto Unix write-bit mask.
    // Preserve all other bits; only toggle write bits (0222).
    const bool makeReadOnly = (NewAttr & 0x01) != 0;
    if (makeReadOnly)
        attrs.permissions &= ~(unsigned long)0222;   // remove all write bits
    else
        attrs.permissions |=  (unsigned long)0200;   // restore at least owner write

    attrs.flags = LIBSSH2_SFTP_ATTR_PERMISSIONS;
    do {
        rc = cs->sftpsession->setstat(nameStr.c_str(), &attrs);
        if (rc == LIBSSH2_ERROR_EAGAIN)
            IsSocketReadable(cs->sock);
    } while (rc == LIBSSH2_ERROR_EAGAIN);

    return (rc == 0) ? SFTP_OK : SFTP_FAILED;
}

int SftpSetDateTimeW(pConnectSettings cs, LPCWSTR RemoteName, LPFILETIME LastWriteTime)
{
    if (!cs || !RemoteName || !LastWriteTime || cs->scponly || IsPhpAgentTransport(cs))
        return SFTP_FAILED;

    std::string nameA(wdirtypemax, '\0');
    CopyStringW2A(cs, RemoteName, nameA.data(), nameA.size());
    ReplaceBackslashBySlash(nameA.data());

    LIBSSH2_SFTP_ATTRIBUTES attr{};
    attr.flags = LIBSSH2_SFTP_ATTR_ACMODTIME;
    attr.mtime = GetUnixTime(LastWriteTime);
    attr.atime = attr.mtime;
    int rc = 0;
    do {
        rc = cs->sftpsession->setstat(nameA.data(), &attr);
        if (rc == LIBSSH2_ERROR_EAGAIN)
            IsSocketReadable(cs->sock);
    } while (rc == LIBSSH2_ERROR_EAGAIN);
    return (rc == 0) ? SFTP_OK : SFTP_FAILED;
}

void SftpGetLastActivePathW(pConnectSettings cs, LPWSTR RelativePath, size_t maxlen)
{
    if (!RelativePath || maxlen == 0)
        return;
    RelativePath[0] = 0;
    if (!cs)
        return;
    wcslcpy(RelativePath, cs->lastactivepath, maxlen - 1);
}

bool SftpChmodW(pConnectSettings cs, LPCWSTR RemoteName, LPCWSTR chmod)
{
    if (!cs || !RemoteName || !chmod || !chmod[0])
        return false;

    // Total Commander sends the mode as octal digits ("755", "4755").
    wchar_t* end = nullptr;
    const unsigned long mode = wcstoul(chmod, &end, 8);
    if (!end || *end != L'\0' || mode > 07777)
        return false;

    std::wstring pathW(RemoteName);
    std::replace(pathW.begin(), pathW.end(), L'\\', L'/');

    // Over SFTP the protocol sets the mode itself, which also works on a
    // server that offers no shell. SCP mode has only the shell.
    if (!cs->scponly && cs->sftpsession) {
        std::string pathA(wdirtypemax, '\0');
        CopyStringW2A(cs, pathW.c_str(), pathA.data(), pathA.size());
        pathA.resize(strlen(pathA.c_str()));
        LIBSSH2_SFTP_ATTRIBUTES attrs{};
        attrs.flags       = LIBSSH2_SFTP_ATTR_PERMISSIONS;
        attrs.permissions = mode;
        int rc = 0;
        do {
            rc = cs->sftpsession->setstat(pathA.c_str(), &attrs);
            if (rc == LIBSSH2_ERROR_EAGAIN)
                IsSocketReadable(cs->sock);
        } while (rc == LIBSSH2_ERROR_EAGAIN);
        SFTP_LOG("CHMOD", "setstat '%s' %lo rc=%d", pathA.c_str(), mode, rc);
        return rc == 0;
    }

    std::wstring cmd = L"chmod ";
    cmd += chmod;
    cmd += L" '";
    cmd += string_util::ShellQuoteSingleW(pathW);
    cmd += L"'";
    // The helper returns chmod's own exit status: only zero is success.
    const int rc = SftpQuoteCommand2W(cs, nullptr, cmd.c_str(), nullptr, 0);
    SFTP_LOG("CHMOD", "shell chmod %ls rc=%d", chmod, rc);
    return rc == 0;
}

bool SftpLinkFolderTargetW(pConnectSettings cs, LPWSTR RemoteName, size_t maxlen)
{
    if (!cs || !RemoteName || maxlen < 2)
        return false;

    const std::wstring_view remoteView(RemoteName);
    // Match both root-level tilde (\~) and tilde anywhere in path (\home\~).
    const bool isTildeHome = (remoteView == L"\\~" || remoteView == L"/~" || remoteView == L"~")
        || remoteView.ends_with(L"\\~") || remoteView.ends_with(L"/~");

    // Real SFTP symlink: resolve via readlink + realpath.
    if (!isTildeHome && cs->sftpsession) {
        std::array<char, wdirtypemax> pathA{};
        CopyStringW2A(cs, RemoteName, pathA.data(), pathA.size() - 1);
        // Normalize separators to forward slashes.
        for (char* p = pathA.data(); *p; ++p)
            if (*p == '\\') *p = '/';

        std::string targetBuf(wdirtypemax, '\0');
        int rc = 0;
        const SYSTICKS start = get_sys_ticks();
        do {
            rc = cs->sftpsession->symlink(pathA.data(), targetBuf.data(),
                                          static_cast<unsigned>(targetBuf.size()) - 1,
                                          LIBSSH2_SFTP_READLINK);
            if (rc == LIBSSH2_ERROR_EAGAIN)
                IsSocketReadable(cs->sock);
        } while (rc == LIBSSH2_ERROR_EAGAIN && get_ticks_between(start) < 5000);

        if (rc <= 0)
            return false;
        targetBuf.resize(static_cast<size_t>(rc));

        // Resolve relative symlink against parent directory.
        if (targetBuf[0] != '/') {
            std::string parent(pathA.data());
            const size_t slash = parent.rfind('/');
            parent = (slash != std::string::npos) ? parent.substr(0, slash + 1) : "/";
            targetBuf = parent + targetBuf;
        }

        // Canonicalize via realpath.
        std::string realBuf(wdirtypemax, '\0');
        const SYSTICKS start2 = get_sys_ticks();
        do {
            rc = cs->sftpsession->realpath(targetBuf.c_str(), realBuf.data(),
                                           static_cast<int>(realBuf.size()) - 1);
            if (rc == LIBSSH2_ERROR_EAGAIN)
                IsSocketReadable(cs->sock);
        } while (rc == LIBSSH2_ERROR_EAGAIN && get_ticks_between(start2) < 5000);

        if (rc > 0) {
            realBuf[static_cast<size_t>(rc)] = '\0';
            CopyStringA2W(cs, realBuf.data(), RemoteName, maxlen);
        } else {
            CopyStringA2W(cs, targetBuf.c_str(), RemoteName, maxlen);
        }
        ReplaceSlashByBackslashW(RemoteName);
        return true;
    }

    if (!isTildeHome)
        return false;

    // --- PHP agent transport: no realpath API available, fall back to server root ---
    if (IsPhpAgentTransport(cs)) {
        wcslcpy(RemoteName, L"/", maxlen - 1);
        return true;
    }

    // --- SCP-only mode: resolve home dir via persistent shell using `echo ~` ---
    if (cs->scponly) {
        if (!EnsureScpShell(cs))
            return false;
        ISshChannel* channel = cs->scpShellChannel.get();
        if (!channel)
            return false;

        static unsigned homeSeq = 1;
        const unsigned seq = homeSeq++;
        std::string endMarker = std::string(kScpListEndMarker) + "_H_" + std::to_string(seq);
        std::string cmd = "echo ~; echo \"" + endMarker + "\"\n";

        size_t written = 0;
        const auto t0 = std::chrono::steady_clock::now();
        while (written < cmd.size()) {
            int n = static_cast<int>(channel->write(cmd.data() + written, cmd.size() - written));
            if (n > 0) {
                written += n;
                continue;
            }
            if (n != LIBSSH2_ERROR_EAGAIN)
                return false;
            if (std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - t0).count() > kScpWriteTimeoutMs)
                return false;
            IsSocketReadable(cs->sock);
        }

        std::vector<std::string> lines;
        ScpReadCommandOutput(cs, endMarker.c_str(), lines, kScpReadTimeoutMs);

        for (const auto& line : lines) {
            if (line.find(kScpListEndMarker) != std::string::npos)
                continue;
            std::string home = line;
            // Strip trailing whitespace / CR / LF
            while (!home.empty() && (home.back() == '\r' || home.back() == '\n' || home.back() == ' '))
                home.pop_back();
            if (home.empty() || home[0] != '/')
                continue;
            CopyStringA2W(cs, home.c_str(), RemoteName, maxlen);
            ReplaceSlashByBackslashW(RemoteName);
            return true;
        }
        return false;
    }

    // --- Standard SFTP: use realpath(".") to resolve the server-side home directory ---
    if (!cs->sftpsession)
        return false;

    std::string realBuf(wdirtypemax, '\0');
    int rc = 0;
    const SYSTICKS start = get_sys_ticks();
    do {
        rc = cs->sftpsession->realpath(".", realBuf.data(),
                                         static_cast<int>(realBuf.size()) - 1);
        if (rc == LIBSSH2_ERROR_EAGAIN)
            IsSocketReadable(cs->sock);
    } while (rc == LIBSSH2_ERROR_EAGAIN && get_ticks_between(start) < 5000);

    if (rc > 0) {
        realBuf[static_cast<size_t>(rc)] = '\0';
        CopyStringA2W(cs, realBuf.data(), RemoteName, maxlen);
        ReplaceSlashByBackslashW(RemoteName);
        return true;
    }

    return false;
}

void SftpShowPropertiesW(pConnectSettings cs, LPCWSTR remotename)
{
    (void)cs;
    (void)remotename;
}

void SftpSetTransferModeW(LPCWSTR mode)
{
    if (!mode || !mode[0])
        return;
    WCHAR ch = mode[0];
    if (ch >= L'a' && ch <= L'z')
        ch = static_cast<WCHAR>(ch - (L'a' - L'A'));
    Global_TransferMode = static_cast<char>(ch & 0xFF);
    if (Global_TransferMode == 'X') {
        wcslcpy(Global_TextTypes.data(), mode + 1, Global_TextTypes.size() - 1);
    }
}

bool SftpSupportsResume(pConnectSettings ConnectSettings)
{
    return ConnectSettings != nullptr;
}

int SftpServerSupportsChecksumsW(pConnectSettings ConnectSettings, LPCWSTR RemoteName)
{
    (void)ConnectSettings;
    (void)RemoteName;
    return 0;
}

HANDLE SftpStartFileChecksumW(int ChecksumType, pConnectSettings ConnectSettings, LPCWSTR RemoteName)
{
    (void)ChecksumType;
    (void)ConnectSettings;
    (void)RemoteName;
    return nullptr;
}

int SftpGetFileChecksumResultW(bool WantResult, HANDLE ChecksumHandle, pConnectSettings ConnectSettings, LPSTR checksum, size_t maxlen)
{
    (void)WantResult;
    (void)ChecksumHandle;
    (void)ConnectSettings;
    if (checksum && maxlen > 0)
        checksum[0] = 0;
    return FS_CHK_ERR_FAIL;
}