#include "global.h"
#include <windows.h>
#include <vector>
#include <algorithm>
#include <cassert>
#include <memory>
#include <string>
#include <chrono>
#include <array>
#include <ws2tcpip.h>
#include <fcntl.h>
#include <stdio.h>
#include "SftpClient.h"
#include "PluginEntryPoints.h"
#include "fsplugin.h"
#include "ServerRegistry.h"
#include "res/resource.h"
#include "CoreUtils.h"
#include "UnicodeHelpers.h"
#include "SftpInternal.h"
#include "IUserFeedback.h"
#if SFTP_EXTRA
#include "PhpAgentClient.h"
#endif
#include "ScpTransfer.h"
#include "ScpTransferInternal.h"
#include "TransferUtils.h"
#include "TextConversion.h"

namespace {

// TU-local derivations from shared constants (defined in ScpTransferInternal.h)
constexpr size_t SFTP_PREFETCH_FACTOR = 64;
constexpr int SFTP_SCP_CHANNEL_OPEN_TIMEOUT_MS = 20000;

// Opens a remote SFTP file, retrying on EAGAIN until the timeout or Escape.
// Shared by the download and upload paths.
std::unique_ptr<ISftpHandle> OpenSftpFileWithRetry(
    pConnectSettings cs,
    const char* path,
    unsigned long flags,
    long mode,
    int timeoutMs = SFTP_SCP_CHANNEL_OPEN_TIMEOUT_MS)
{
    std::unique_ptr<ISftpHandle> handle;
    const SYSTICKS start = get_sys_ticks();
    do {
        handle = cs->sftpsession->open(path, flags, mode);
        if (handle) break;
        const int err = cs->session->lastErrno();
        // In nonblocking mode, some servers/transports can transiently
        // report no concrete errno here. Treat err==0 like EAGAIN and retry.
        if (err != LIBSSH2_ERROR_EAGAIN && err != 0) {
            SftpLogLastError("SFTP open failed: ", err);
            break;
        }
        if (EscapePressed() || get_ticks_between(start) > timeoutMs) {
            ShowStatusId(IDS_LOG_SFTP_OPEN_TIMEOUT, nullptr, true);
            break;
        }
        IsSocketReadable(cs->sock);
    } while (!handle);
    return handle;
}

// RAII wrapper for local file handle
class LocalFile {
public:
    LocalFile() = default;
    explicit LocalFile(HANDLE h) : handle_(h) {}
    ~LocalFile() { if (IsValid()) CloseHandle(handle_); }

    LocalFile(const LocalFile&) = delete;
    LocalFile& operator=(const LocalFile&) = delete;

    LocalFile(LocalFile&& other) noexcept : handle_(std::exchange(other.handle_, INVALID_HANDLE_VALUE)) {}

    bool Open(LPCWSTR path, DWORD access, DWORD share, DWORD creation, DWORD flags) {
        handle_ = CreateFileT(path, access, share, nullptr, creation, flags, nullptr);
        return IsValid();
    }

    bool IsValid() const noexcept { return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE; }
    HANDLE get() const noexcept { return handle_; }
    HANDLE release() noexcept { return std::exchange(handle_, INVALID_HANDLE_VALUE); }

    int64_t GetSize() const {
        LARGE_INTEGER li{};
        return GetFileSizeEx(handle_, &li) ? li.QuadPart : -1;
    }

    bool Seek(int64_t offset) {
        LARGE_INTEGER li{};
        li.QuadPart = offset;
        return SetFilePointerEx(handle_, li, nullptr, FILE_BEGIN) != FALSE;
    }

private:
    HANDLE handle_ = INVALID_HANDLE_VALUE;
};

// RAII wrapper for a remote SFTP handle. Close() sends SSH_FXP_CLOSE and
// waits on the socket for the server's answer: only then has the server
// closed the file, and for an upload the answer is where a failed final
// write shows. A close that times out or is cancelled leaves the rest to
// ~Libssh2SftpHandle().
class RemoteSftpFile {
public:
    RemoteSftpFile(std::unique_ptr<ISftpHandle> h, pConnectSettings cs) : handle_(std::move(h)), cs_(cs) {}
    ~RemoteSftpFile() { if (handle_) Close(); }

    RemoteSftpFile(const RemoteSftpFile&) = delete;
    RemoteSftpFile& operator=(const RemoteSftpFile&) = delete;

    ISftpHandle* get() const { return handle_.get(); }

    int Close() {
        if (!handle_) return 0;
        const int rc = WaitForOperation([this] { return handle_->close(); },
                                        SFTP_CLOSE_TIMEOUT_MS, cs_);
        handle_.reset();
        return rc;
    }

private:
    std::unique_ptr<ISftpHandle> handle_;
    pConnectSettings cs_;
};

// RAII wrapper for remote SCP channel. Adds explicit timeout-driven close
// (sendEof / waitEof / channelClose / channelFree) with socket yielding;
// destructor of bare Libssh2Channel performs only a bounded tight-loop free.
// Kept because SCP servers can be timing-sensitive on teardown.
class RemoteScpChannel {
public:
    explicit RemoteScpChannel(std::unique_ptr<ISshChannel> ch, pConnectSettings cs)
        : channel_(std::move(ch)), cs_(cs) {}
    ~RemoteScpChannel() { Close(); }

    RemoteScpChannel(const RemoteScpChannel&) = delete;
    RemoteScpChannel& operator=(const RemoteScpChannel&) = delete;

    ISshChannel* get() const { return channel_.get(); }

    int Close() {
        if (!channel_ || !cs_) return 0;
        // Attempt graceful shutdown
        WaitForOperation([this] { return channel_->sendEof(); }, 1000, cs_);
        WaitForOperation([this] { return channel_->waitEof(); }, 1000, cs_);
        WaitForOperation([this] { return channel_->channelClose(); }, 1000, cs_);
        // Explicit drained channelFree() — see class header comment.
        WaitForOperation([this] { return channel_->channelFree(); }, 2000, cs_);
        channel_.reset();
        return 0;
    }

private:
    std::unique_ptr<ISshChannel> channel_;
    pConnectSettings cs_;
};

// Helper to display transfer start status
void ShowTransferStart(bool scp, LPCWSTR name, int resId)
{
    std::array<char, MAX_PATH> abuf{};
    std::array<WCHAR, wdirtypemax> wbuf{};
    LoadStr(abuf, resId);
    iwlcopy(wbuf.data(), abuf.data(), wdirtypemax - 1);
    if (scp)
        wcslcat(wbuf.data(), L" (SCP)", wdirtypemax);
    wcslcat(wbuf.data(), name, wdirtypemax - 1);
    std::replace(wbuf.begin(), wbuf.end(), L'\\', L'/');
    ShowStatusW(wbuf.data());
}

// Policy decisions for download/upload
bool ResolveScpPolicy(pConnectSettings cs, int64_t filesize, bool resume, bool& useScp)
{
    if (!cs) return false;
    if (useScp && resume && !cs->scponly)
        useScp = false;
    if (!useScp || filesize <= (1LL << 31))
        return true;

    // >2GB handling
    if (!SSH_ScpNo2GBLimit || (cs->scpserver64bit != 1 && !cs->scpserver64bittemporary)) {
        if (!SSH_ScpNo2GBLimit) {
            if (cs->scponly) {
                ShowErrorId(IDS_DLL_VERSION);
                return false;
            }
            useScp = false;
            return true;
        }
        if (cs->scponly) {
            std::array<char, 256> err{};
            LoadStr(err, IDS_NO_2GB_SUPPORT);
            if (!AskUserYesNo(cs, "SFTP Error", err.data()))
                return false;
            cs->scpserver64bittemporary = true;
        }
    }
    return true;
}

// Open local file for download: appended to on resume, otherwise created anew.
bool OpenLocalForWrite(LocalFile& file, LPCWSTR path, bool resume,
                       int64_t& loaded, int64_t filesize)
{
    loaded = 0;
    if (resume) {
        if (!file.Open(path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN))
            return false;
        loaded = file.GetSize();
        if (loaded < 0) return false;
        if (filesize <= loaded) {
            // Already complete or larger
            return false;
        }
        if (!file.Seek(loaded))
            return false;
        return true;
    }
    return file.Open(path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                     CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN);
}

// Download data loop (common for SFTP and SCP)
template<typename Handle>
int DownloadLoop(pConnectSettings cs, Handle& remote, LocalFile& local,
                 LPCWSTR remoteName, LPCWSTR localName,
                 bool& textMode, int64_t totalSize, int64_t& loaded,
                 int64_t& scpRemain)
{
    const size_t blockSize = SFTP_MAX_READ_SIZE * SFTP_PREFETCH_FACTOR;
    std::vector<char> buffer(blockSize);
    // What goes to disk is decided and converted by `text`, into its own
    // buffer: LF -> CRLF can double a block.
    std::vector<char> converted;
    text_conversion::DownloadText text(textMode);
    const auto writeOut = [&]() {
        DWORD written = 0;
        const bool ok = converted.empty() ||
            (WriteFile(local.get(), converted.data(), static_cast<DWORD>(converted.size()), &written, nullptr) &&
             written == static_cast<DWORD>(converted.size()));
        converted.clear();
        return ok;
    };
    int ret = SFTP_OK;
    auto lastProgress = std::chrono::steady_clock::now();

    while (true) {
        int len = 0;
        if constexpr (std::is_same_v<Handle, RemoteScpChannel>) {
            if (scpRemain <= 0) break;
            len = static_cast<int>(remote.get()->read(buffer.data(),
                static_cast<size_t>(std::min<int64_t>(scpRemain, static_cast<int64_t>(blockSize)))));
            if (len > 0) scpRemain -= len;
        } else {
            len = static_cast<int>(remote.get()->read(buffer.data(), blockSize));
        }

        if (len > 0) {
            lastProgress = std::chrono::steady_clock::now();
            loaded += len;
            text.Feed(buffer.data(), static_cast<size_t>(len), converted);
            if (!writeOut()) {
                ret = SFTP_WRITEFAILED;
                break;
            }
        } else if (len == LIBSSH2_ERROR_EAGAIN) {
            if constexpr (std::is_same_v<Handle, RemoteScpChannel>) {
                const auto now = std::chrono::steady_clock::now();
                const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastProgress).count();
                if (elapsed > SFTP_SCP_READ_IDLE_TIMEOUT_MS) {
                    ShowStatusId(IDS_LOG_SCP_DL_TIMEOUT, nullptr, true);
                    ret = SFTP_READFAILED;
                    break;
                }
            }
            IsSocketReadable(cs->sock);
        } else if (len < 0) {
            SftpLogLastError("Download read error: ", len);
            ret = SFTP_READFAILED;
            break;
        } else { // len == 0, EOF
            break;
        }

        if (UpdatePercentBar(cs, GetPercent(loaded, totalSize), remoteName, localName)) {
            ret = SFTP_ABORT;
            break;
        }
    }
    text.Finish(converted);
    if (!writeOut() && ret == SFTP_OK)
        ret = SFTP_WRITEFAILED;
    textMode = text.Text();
    return ret;
}

} // anonymous namespace

int SftpDownloadFileW(pConnectSettings cs, LPCWSTR RemoteName, LPCWSTR LocalName,
                      int64_t filesize, LPFILETIME ft, bool Resume, bool binary)
{
    if (!cs) return SFTP_FAILED;
#if SFTP_EXTRA
    if (IsPhpAgentTransport(cs))
        return PhpAgentDownloadFileW(cs, RemoteName, LocalName, true, filesize, Resume);
#endif

    // Converted text has different offsets on each side, so a text file is
    // never continued: a resume asked for becomes a transfer from the start.
    // Decided first, since a resume also picks the transfer path below.
    bool textMode = !binary && (cs->unixlinebreaks == 1) && SftpDetermineTransferModeW(RemoteName);
    if (textMode && Resume) {
        SFTP_LOG("SFTP", "Download: text mode, resume becomes a full transfer");
        Resume = false;
    }

    const bool forceShellFallback = (cs->scponly && cs->shell_transfer_force && cs->shell_transfer_dd) ||
                                    (cs->scponly && Resume);
    bool useScp = cs->scpfordata;
    if (!ResolveScpPolicy(cs, filesize, Resume, useScp))
        return SFTP_ABORT;

    ShowTransferStart(useScp, RemoteName, IDS_DOWNLOAD);

    std::string remotePath = ToRemotePathA(cs, RemoteName);
    if (remotePath.empty())
        return SFTP_FAILED;

    if (!ReconnectSFTPChannelIfNeeded(cs))
        return SFTP_FAILED;

    if (useScp && !PrepareScpTransferSession(cs))
        return SFTP_FAILED;

    // The remote file is opened before the local one is created, so a file
    // the server refuses to read leaves no empty local file behind and does
    // not truncate a local file about to be overwritten. The shell paths open
    // the remote side themselves and come after the local file.
    const bool shellPath = forceShellFallback || (useScp && cs->scponly);
    std::unique_ptr<ISftpHandle> sftpHandle;
    std::unique_ptr<ISshChannel> scpHandle;
    libssh2_struct_stat scpInfo{};
    int64_t scpRemain = 0;

    if (!shellPath) {
        if (useScp) {
            if (!OpenScpDownloadChannel(cs, remotePath.c_str(), scpHandle, &scpInfo))
                return SFTP_READFAILED;
            scpRemain = scpInfo.st_size;
        } else {
            sftpHandle = OpenSftpFileWithRetry(cs, remotePath.c_str(), LIBSSH2_FXF_READ, 0);
            if (!sftpHandle)
                return SFTP_READFAILED;
        }
    }

    // A shell path learns that the remote file cannot be read only once it
    // runs, after the local file is opened. One that would be overwritten is
    // therefore left alone until the download is complete: the data goes to
    // a file beside it, under a name no other file has, which replaces it at
    // the end.
    const bool viaTemp = shellPath && !Resume &&
                         GetFileAttributesT(LocalName) != INVALID_FILE_ATTRIBUTES;
    std::wstring tempName;
    if (viaTemp) {
        for (unsigned n = 0; n < 100; ++n) {
            tempName = std::format(L"{}.sftp-part-{:x}-{:x}", LocalName, GetCurrentProcessId(),
                                   static_cast<unsigned>(GetTickCount64()) + n);
            if (GetFileAttributesT(tempName.c_str()) == INVALID_FILE_ATTRIBUTES)
                break;
        }
    }
    const LPCWSTR target = viaTemp ? tempName.c_str() : LocalName;

    // A file being overwritten is removed rather than truncated in place:
    // CREATE_ALWAYS is refused on a hidden or system file.
    if (!Resume)
        DeleteFileT(target);

    // Open local file
    LocalFile local;
    int64_t loaded = 0;
    if (!OpenLocalForWrite(local, target, Resume, loaded, filesize)) {
        if (Resume && loaded == filesize)
            return SFTP_OK;
        return SFTP_WRITEFAILED;
    }

    if (shellPath) {
        int rc;
        if (forceShellFallback) {
            int64_t shellLoaded = loaded;
            rc = ShellDdDownloadFile(cs, remotePath, RemoteName,
                                     local.get(), LocalName, filesize, loaded, textMode, &shellLoaded);
        } else {
            // Shell SCP path
            rc = ShellScpDownloadFile(cs, BuildShellScpArgument(remotePath), RemoteName,
                                      local.get(), LocalName,
                                      textMode, filesize, &loaded);
        }
        // The file keeps the server's modification time, as over SFTP.
        if (rc == SFTP_OK && ft)
            SetFileTime(local.get(), nullptr, nullptr, ft);
        if (viaTemp) {
            CloseHandle(local.release());
            if (rc != SFTP_OK) {
                DeleteFileT(tempName.c_str());
                return rc;
            }
            // One step: the old copy stays until the new one takes its
            // place. A replace that fails leaves both, the new one beside it.
            if (!MoveFileReplaceT(tempName.c_str(), LocalName)) {
                SFTP_LOG("XFER", "replacing the local file failed (error %lu); download kept beside it",
                         GetLastError());
                return SFTP_WRITEFAILED;
            }
            return rc;
        }
        // A failure that wrote nothing removes the file it created rather
        // than leave an empty one behind.
        if (rc != SFTP_OK && !Resume && local.GetSize() == 0) {
            CloseHandle(local.release());
            DeleteFileT(LocalName);
        }
        return rc;
    }

    if (!useScp && Resume && loaded > 0) {
        sftpHandle->seek(static_cast<uint64_t>(loaded));
        if (static_cast<int64_t>(sftpHandle->tell()) != loaded)
            return SFTP_READFAILED;
    }

    // Download loop
    int ret = SFTP_OK;
    if (useScp) {
        RemoteScpChannel remoteScp(std::move(scpHandle), cs);
        ret = DownloadLoop(cs, remoteScp, local, RemoteName, LocalName,
                           textMode, filesize, loaded, scpRemain);
        // The channel ending before the announced size is a short file, not
        // a finished one. After the data scp sends one status byte: zero for
        // a file read whole, otherwise an error with a message — a server
        // that failed to read pads the rest with zeros, so the size alone
        // does not tell. A server that sends no byte at all is taken at the
        // size it announced.
        if (ret == SFTP_OK && scpRemain > 0) {
            SFTP_LOG("SCP", "Download ended %lld bytes short", static_cast<long long>(scpRemain));
            ret = SFTP_READFAILED;
        } else if (ret == SFTP_OK) {
            char status = 0;
            if (ScpReadByte(remoteScp.get(), cs, &status, SFTP_SCP_READ_IDLE_TIMEOUT_MS) &&
                status != 0)
            {
                std::string err;
                ScpReadLine(remoteScp.get(), cs, err, SFTP_SCP_READ_IDLE_TIMEOUT_MS);
                SFTP_LOG("SCP", "Download status %d: %s", status, err.c_str());
                if (!err.empty())
                    ShowStatus(err.c_str());
                ret = SFTP_READFAILED;
            }
        }
    } else {
        RemoteSftpFile remoteSftp(std::move(sftpHandle), cs);
        int64_t dummyRemain = 0; // not used for SFTP
        ret = DownloadLoop(cs, remoteSftp, local, RemoteName, LocalName,
                           textMode, filesize, loaded, dummyRemain);
    }

    // Close remote (RAII handles will close automatically)
    if (ret == SFTP_OK && ft)
        SetFileTime(local.get(), nullptr, nullptr, ft);

    if (ret == SFTP_READFAILED && loaded > 0 && loaded < filesize && !cs->scponly)
        ret = SFTP_PARTIAL;

    return ret;
}

int SftpUploadFileW(pConnectSettings cs, LPCWSTR LocalName, LPCWSTR RemoteName,
                    bool Resume, bool setattr, bool binary)
{
    if (!cs) return SFTP_FAILED;
#if SFTP_EXTRA
    if (IsPhpAgentTransport(cs))
        return PhpAgentUploadFileW(cs, LocalName, RemoteName, Resume);
#endif

    // Converted text has different offsets on each side, so a text file is
    // never continued: a resume asked for becomes a transfer from the start.
    // Decided first, since a resume also picks the transfer path below.
    bool textMode = !binary && (cs->unixlinebreaks == 1) && SftpDetermineTransferModeW(LocalName);
    if (textMode && Resume) {
        SFTP_LOG("SFTP", "Upload: text mode, resume becomes a full transfer");
        Resume = false;
    }

    const bool forceShellFallback = (cs->scponly && cs->shell_transfer_force && cs->shell_transfer_dd) ||
                                    (cs->scponly && Resume);
    bool useScp = cs->scpfordata;
    if (useScp && Resume && !cs->scponly)
        useScp = false;

    // Open local file
    LocalFile local;
    if (!local.Open(LocalName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN)) {
        return SFTP_READFAILED;
    }

    int64_t filesize = local.GetSize();
    if (filesize < 0) return SFTP_READFAILED;

    if (!ResolveScpPolicy(cs, filesize, Resume, useScp))
        return SFTP_ABORT;

    ShowTransferStart(useScp, RemoteName, IDS_UPLOAD);

    std::string remotePath = ToRemotePathA(cs, RemoteName);
    if (remotePath.empty())
        return SFTP_WRITEFAILED;

    // The local file's modification time, kept on the server when TC asks
    // for attributes to be set.
    long localMtime = 0;
    if (setattr) {
        FILETIME lft;
        if (GetFileTime(local.get(), nullptr, nullptr, &lft))
            localMtime = GetUnixTime(&lft);
    }

    if (forceShellFallback) {
        int64_t shellUploaded = 0;
        const int rc = ShellDdUploadFile(cs, remotePath, RemoteName,
                                         local.get(), LocalName, filesize, Resume ? 1 : 0, textMode, &shellUploaded);
        if (rc == SFTP_OK && localMtime && !ShellSetRemoteMtime(cs, remotePath, localMtime))
            SFTP_LOG("SHELL", "upload: modification time not set");
        return rc;
    }

    if (!ReconnectSFTPChannelIfNeeded(cs))
        return SFTP_FAILED;

    if (useScp && !PrepareScpTransferSession(cs))
        return SFTP_FAILED;

    // SCP announces the size before the data, so a text upload is measured
    // with the very converter that will produce it.
    int64_t uploadSize = filesize;
    if (textMode) {
        int64_t converted = 0;
        if (MeasureTextUpload(local.get(), converted))
            uploadSize = converted;
        else
            textMode = false;
    }

    // Open remote
    std::unique_ptr<ISftpHandle> sftpHandle;
    std::unique_ptr<ISshChannel> scpHandle;
    int64_t resumeOffset = 0;

    if (useScp) {
        if (cs->scponly) {
            // Shell SCP upload
            return ShellScpUploadFile(cs, BuildShellScpArgument(remotePath), RemoteName,
                                      local.get(), LocalName, uploadSize, textMode, &filesize,
                                      localMtime);
        } else {
            // Native SCP upload
            FILETIME ft;
            long mtime = 0;
            if (setattr && GetFileTime(local.get(), nullptr, nullptr, &ft))
                mtime = GetUnixTime(&ft);
            // The session is non-blocking, so opening the channel answers
            // EAGAIN until the server has started scp. It is asked again, as
            // the download side does, until it opens or the wait runs out;
            // taking the first EAGAIN for a refusal failed nearly every upload.
            const auto openStart = std::chrono::steady_clock::now();
            int openErr = 0;
            while (true) {
                scpHandle = cs->session->scpSend64(remotePath.c_str(), cs->filemod,
                                                   static_cast<uint64_t>(uploadSize), mtime, 0);
                if (scpHandle)
                    break;
                openErr = cs->session->lastErrno();
                if (openErr != LIBSSH2_ERROR_EAGAIN || EscapePressed())
                    break;
                const auto waited = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - openStart).count();
                if (waited > SFTP_SCP_CHANNEL_OPEN_TIMEOUT_MS) {
                    ShowStatusId(IDS_LOG_SCP_OPEN_TIMEOUT, nullptr, true);
                    break;
                }
                IsSocketReadable(cs->sock);
            }
            if (!scpHandle) {
                SFTP_LOG("SCP", "Upload: the scp channel did not open (%d)", openErr);
                SftpLogLastError("SCP upload error: ", openErr);
                return SFTP_WRITEFAILED;
            }
        }
    } else {
        unsigned long flags = LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT;
        if (!Resume)
            flags |= LIBSSH2_FXF_TRUNC;

        sftpHandle = OpenSftpFileWithRetry(cs, remotePath.c_str(), flags, 0644);
        if (!sftpHandle)
            return SFTP_WRITEFAILED;

        if (Resume) {
            // Get remote size and seek
            LIBSSH2_SFTP_ATTRIBUTES attr{};
            // Request both permissions AND size from server
            attr.flags = LIBSSH2_SFTP_ATTR_PERMISSIONS | LIBSSH2_SFTP_ATTR_SIZE;
            int rc;
            do {
                rc = sftpHandle->fstat(&attr, 0);
                if (rc == LIBSSH2_ERROR_EAGAIN)
                    IsSocketReadable(cs->sock);
            } while (rc == LIBSSH2_ERROR_EAGAIN);
            // Resuming continues a remote file that is a prefix of this one.
            // A size the server does not report, or one larger than the local
            // file, means it is not: the file is opened without truncation,
            // so writing from the start would leave the old tail behind.
            if (rc != 0 || !(attr.flags & LIBSSH2_SFTP_ATTR_SIZE))
                return SFTP_WRITEFAILED;
            const int64_t remoteSize = static_cast<int64_t>(attr.filesize);
            if (remoteSize > filesize)
                return SFTP_WRITEFAILED;
            if (remoteSize > 0) {
                // Writing anywhere but at the end of what is there would put
                // the rest of the file in the middle of it.
                sftpHandle->seek(static_cast<uint64_t>(remoteSize));
                if (sftpHandle->tell() != static_cast<uint64_t>(remoteSize))
                    return SFTP_WRITEFAILED;
                if (!local.Seek(remoteSize))
                    return SFTP_READFAILED;
                resumeOffset = remoteSize;
            }
        }
    }

    // Upload loop
    std::vector<char> buffer(SFTP_MAX_WRITE_SIZE * 32);
    std::vector<char> converted;
    text_conversion::CrLfToLf toLf;
    int64_t sent = resumeOffset; // start from resume offset so progress bar is correct
    int64_t emitted = 0;         // bytes handed to the server after conversion
    bool atEof = false;
    auto lastProgress = std::chrono::steady_clock::now();
    int ret = SFTP_OK;

    while (!atEof) {
        DWORD read = 0;
        if (!ReadFile(local.get(), buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr)) {
            SFTP_LOG("SFTP", "Upload: local read failed at %lld (%lu)",
                     static_cast<long long>(sent), GetLastError());
            ret = SFTP_READFAILED;
            break;
        }
        atEof = (read == 0);

        // In text mode a CR ending one chunk waits for the next to show
        // whether an LF follows; end of file releases it.
        const char* data = buffer.data();
        size_t toWrite = read;
        if (textMode) {
            converted.clear();
            toWrite = atEof ? toLf.Finish(converted) : toLf.Convert(buffer.data(), read, converted);
            data = converted.data();
        }
        size_t written = 0;
        while (written < toWrite) {
            int w = 0;
            if (useScp)
                w = static_cast<int>(scpHandle->write(data + written, toWrite - written));
            else
                w = static_cast<int>(sftpHandle->write(data + written, toWrite - written));

            if (w > 0) {
                written += static_cast<size_t>(w);
                lastProgress = std::chrono::steady_clock::now();
            } else if (w == LIBSSH2_ERROR_EAGAIN) {
                if (useScp) {
                    const auto now = std::chrono::steady_clock::now();
                    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastProgress).count();
                    if (elapsed > SFTP_SCP_WRITE_IDLE_TIMEOUT_MS) {
                        ShowStatusId(IDS_LOG_SCP_UL_TIMEOUT, nullptr, true);
                        ret = SFTP_WRITEFAILED;
                        break;
                    }
                }
                // libssh2 is often waiting to read here (a window adjust from
                // the server), not to write: wait for whichever it names.
                WaitForSshIo(cs);
            } else {
                SftpLogLastError("Upload write error: ", w);
                ret = SFTP_WRITEFAILED;
                break;
            }
        }

        if (ret != SFTP_OK) break;
        sent += read; // count original bytes for progress
        emitted += static_cast<int64_t>(written);
        if (UpdatePercentBar(cs, GetPercent(sent, filesize), LocalName, RemoteName)) {
            ret = SFTP_ABORT;
            break;
        }
    }

    // End of file is only a success when it falls where the file was measured
    // to end; anything else is a file that changed under the upload. For SCP
    // the converted byte count must also equal the size the header announced.
    if (ret == SFTP_OK && sent != filesize) {
        SFTP_LOG("SFTP", "Upload: sent %lld of %lld bytes",
                 static_cast<long long>(sent), static_cast<long long>(filesize));
        ret = SFTP_READFAILED;
    }
    if (ret == SFTP_OK && useScp && emitted != uploadSize) {
        SFTP_LOG("SCP", "Upload: emitted %lld bytes, header announced %lld",
                 static_cast<long long>(emitted), static_cast<long long>(uploadSize));
        ret = SFTP_READFAILED;
    }

    // scp's receiving side writes the file, then waits for a zero byte from
    // us and answers it; that answer is where a full disk or a quota shows.
    // The shell-driven path returned earlier and does its own handshake.
    if (ret == SFTP_OK && useScp) {
        std::string err;
        if (!ScpSendAck(scpHandle.get(), cs) || !ScpReadAck(scpHandle.get(), cs, err)) {
            SFTP_LOG("SCP", "Upload not acknowledged: %s", err.c_str());
            if (!err.empty())
                ShowStatus(err.c_str());
            ret = SFTP_WRITEFAILED;
        }
    }

    // The upload is done only when the server has closed the file: its answer
    // to the close carries the result of the last writes, and until then the
    // file may still be open on the server. Times and permissions are set
    // after that, on the closed file.
    if (sftpHandle) {
        RemoteSftpFile remoteSftp(std::move(sftpHandle), cs);
        const int closeRc = remoteSftp.Close();
        if (closeRc != 0 && ret == SFTP_OK) {
            SFTP_LOG("SFTP", "Upload: closing the remote file failed rc=%d", closeRc);
            ret = SFTP_WRITEFAILED;
        }
    }

    if (ret == SFTP_OK && setattr) {
        // SFTP sets times and permissions on the closed file; SCP sent the
        // time with the file, and the shell paths returned above.
        if (!useScp && cs->sftpsession != nullptr) {
            FILETIME ft;
            if (GetFileTime(local.get(), nullptr, nullptr, &ft)) {
                LIBSSH2_SFTP_ATTRIBUTES attr{};
                attr.flags = LIBSSH2_SFTP_ATTR_ACMODTIME | (setattr ? LIBSSH2_SFTP_ATTR_PERMISSIONS : 0);
                attr.mtime = GetUnixTime(&ft);
                attr.atime = attr.mtime;
                if (setattr) attr.permissions = cs->filemod;
                do {
                    int rc = cs->sftpsession->setstat(remotePath.c_str(), &attr);
                    if (rc != LIBSSH2_ERROR_EAGAIN) break;
                    IsSocketReadable(cs->sock);
                } while (true);
            }
        }
    }

    return ret;
}