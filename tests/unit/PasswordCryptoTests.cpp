#include "Test.h"

#include <windows.h>
#include <string>
#include <vector>

// The plugin's stored-password functions (SftpInternal.h), declared here so
// the test does not pull in the plugin's headers.
void EncryptString(LPCSTR pszPlain, LPSTR pszEncrypted, UINT cchEncrypted);
void DecryptString(LPCSTR pszEncrypted, LPSTR pszPlain, UINT cchPlain);

namespace {

std::string Encrypt(const std::string& plain)
{
    std::vector<char> out(16384);
    EncryptString(plain.c_str(), out.data(), static_cast<UINT>(out.size()));
    return out.data();
}

std::string Decrypt(const std::string& stored, UINT size = 16384)
{
    std::vector<char> out(size);
    DecryptString(stored.c_str(), out.data(), size);
    return out.data();
}

} // namespace

TEST_CASE("password: DPAPI round trip, UTF-8 and long values")
{
    for (const std::string plain : { std::string("secret"), std::string("p\xC3\xA4ss w\xC3\xB6rd \xC4\x85\xC4\x99"),
                                     std::string(3000, 'x') }) {
        const std::string stored = Encrypt(plain);
        CHECK(stored.starts_with("dpapi:"));
        CHECK(stored.find(plain) == std::string::npos);
        CHECK_BYTES(Decrypt(stored), plain);
    }
}

TEST_CASE("password: empty stays empty")
{
    CHECK_BYTES(Decrypt(Encrypt("")), "");
    CHECK_BYTES(Decrypt(""), "");
}

TEST_CASE("password: legacy XOR format of older releases still reads")
{
    // Worked by hand from the published key "unpz...": the key is read from
    // offset (length mod key length), each byte written as three digits.
    CHECK_BYTES(Decrypt("015"), "a");       // 'a' ^ 'n' = 15
    CHECK_BYTES(Decrypt("017024"), "ab");   // 'a' ^ 'p' = 17, 'b' ^ 'z' = 24
}

TEST_CASE("password: plain prefix and malformed values")
{
    CHECK_BYTES(Decrypt("plain:abc def"), "abc def");
    CHECK_BYTES(Decrypt("dpapi:not base64 !!"), "");
    CHECK_BYTES(Decrypt("dpapi:AAAA"), "");  // valid base64, not a DPAPI blob
    CHECK_BYTES(Decrypt("12"), "");          // not whole triplets
    CHECK_BYTES(Decrypt("999"), "");         // a triplet above 255
    CHECK_BYTES(Decrypt("01a"), "");
    CHECK_BYTES(Decrypt("!"), "");           // TC's password store, absent here
}

TEST_CASE("password: a result that does not fit is not cut")
{
    const std::string stored = Encrypt("0123456789");
    CHECK_BYTES(Decrypt(stored, 11), "0123456789");
    CHECK_BYTES(Decrypt(stored, 10), "");
    CHECK_BYTES(Decrypt("plain:0123456789", 10), "");
}
