#pragma once

#include <windows.h>
#include <string>
#include <memory>
#include "SftpClient.h"

bool PrepareScpTransferSession(pConnectSettings cs);
bool OpenScpDownloadChannel(
    pConnectSettings ConnectSettings,
    const char* filename,
    std::unique_ptr<ISshChannel>& outChannel,
    libssh2_struct_stat* outInfo);

int ShellDdDownloadFile(
    pConnectSettings cs,
    const std::string& remotePathArg,
    LPCWSTR remoteNameW,
    HANDLE localfile,
    LPCWSTR localNameW,
    int64_t fileSize,
    int64_t resumeFrom,
    bool textMode,
    int64_t* outSizeLoaded);

int ShellDdUploadFile(
    pConnectSettings cs,
    const std::string& remotePathArg,
    LPCWSTR remoteNameW,
    HANDLE localfile,
    LPCWSTR localNameW,
    int64_t fileSize,
    int64_t resumeFrom,
    bool textMode,
    int64_t* outSizeLoaded);

int ShellScpDownloadFile(
    pConnectSettings cs,
    const std::string& remotePathArg,
    LPCWSTR remoteNameW,
    HANDLE localfile,
    LPCWSTR localNameW,
    bool textMode,
    int64_t hintedFileSize,
    int64_t* outSizeLoaded);

// `mtime`, when not 0, is sent as the file's modification time (scp -p).
int ShellScpUploadFile(
    pConnectSettings cs,
    const std::string& remotePathArg,
    LPCWSTR remoteNameW,
    HANDLE localfile,
    LPCWSTR localNameW,
    int64_t fileSize,
    bool textMode,
    int64_t* outSizeLoaded,
    long mtime);

// Sets the modification time (Unix seconds) of a file the shell transfer
// wrote; false when the server's `touch` refused it.
bool ShellSetRemoteMtime(pConnectSettings cs, const std::string& remotePath, long mtime);
