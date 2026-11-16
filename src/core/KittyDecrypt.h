#pragma once
#include <string>

// Try to decrypt a KiTTY base64 password with each key derivation mode in
// turn, taking the first that gives text a user could have typed. Returns
// true and fills `out` with plaintext on success.
[[nodiscard]] bool DecryptKittyPassword(const std::string& enc,
                                   const std::string& host,
                                   const std::string& term,
                                   std::string&       out);
