#include "Test.h"
#include "../../src/core/KittyDecrypt.h"

#include <random>
#include <string>

// A wrong key still decodes to something; the decoder keeps only text a
// user could have typed. Random input stands in for a password stored with
// the other key: whatever comes back has no control bytes, and most of it is
// refused outright.
TEST_CASE("kitty: a decode that is not typed text is refused")
{
    static const char alphabet[] = "AZERTYUIOPQSDFGHJKLMWXCVBNazertyuiopqsdfghjklmwxcvbn0123456789+/";
    std::mt19937 rng(12345);
    std::uniform_int_distribution<size_t> pick(0, sizeof(alphabet) - 2);
    int refused = 0;
    for (int i = 0; i < 200; ++i) {
        std::string enc;
        for (int k = 0; k < 24; ++k)
            enc += alphabet[pick(rng)];
        std::string out;
        if (!DecryptKittyPassword(enc, "host.example", "xterm", out)) {
            ++refused;
            CHECK(out.empty());
            continue;
        }
        bool typed = true;
        for (unsigned char c : out)
            typed = typed && c >= 0x20 && c != 0x7F;
        CHECK(typed);
    }
    CHECK(refused > 100);
}

TEST_CASE("kitty: empty input is no password")
{
    std::string out;
    CHECK(!DecryptKittyPassword("", "host", "xterm", out));
    CHECK(out.empty());
}
