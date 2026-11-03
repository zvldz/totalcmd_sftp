#pragma once
#include <windows.h>
#include <stddef.h>
#include <string>

// Native PuTTY PPK -> temporary PEM converter for libssh2_userauth_publickey_fromfile.
// Supports PPK v2 and v3.
// Output: traditional PEM for RSA/ECDSA keys.

enum class PpkConvertError : int {
    ok = 0,
    io_error,
    unsupported_version,
    unsupported_algorithm,
    unsupported_encryption,
    unsupported_kdf,
    kdf_unavailable,
    passphrase_required,
    bad_passphrase_or_mac,
    invalid_format,
    crypto_error,
    internal_error,
};

// Converts a PPK file to an unencrypted private key in PEM / OpenSSH form,
// in memory only — it never touches the disk. The caller wipes `outPem`
// after use.
// ppkPath: internal string.
// passphrase: passphrase for encrypted keys (null/empty for unencrypted keys).
// outError: optional detailed status.
bool ConvertPpkToOpenSsh(const char* ppkPath, const char* passphrase,
                         std::string& outPem, PpkConvertError* outError) noexcept;
