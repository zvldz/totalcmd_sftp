#include "Test.h"
#include "Utf8Escape.h"

#include <string>

using utf8_escape::Decode;
using utf8_escape::Encode;

TEST_CASE("utf8 escape: valid text is plain UTF-16")
{
    CHECK(Decode("plain.txt") == L"plain.txt");
    CHECK(Decode("\xD0\xBA\xD0\xB8\xD1\x80") == L"\x043A\x0438\x0440");
    CHECK(Decode("\xF0\x9F\x98\x80") == L"\xD83D\xDE00");
    CHECK_BYTES(Encode(L"\x043A\x0438\x0440"), "\xD0\xBA\xD0\xB8\xD1\x80");
    CHECK_BYTES(Encode(L"\xD83D\xDE00"), "\xF0\x9F\x98\x80");
}

TEST_CASE("utf8 escape: bytes that are not UTF-8 become stand-ins and come back")
{
    // "café" written in cp1252, a lone continuation byte, an overlong '/',
    // a UTF-16 surrogate encoded in UTF-8, a sequence cut at the end.
    for (const std::string bytes : { std::string("caf\xE9"), std::string("a\x80z"),
                                     std::string("\xC0\xAF"), std::string("\xED\xA0\x80"),
                                     std::string("cut\xE2\x82") }) {
        const std::wstring text = Decode(bytes);
        CHECK(text.find(L'\xFFFD') == std::wstring::npos);
        CHECK_BYTES(Encode(text), bytes);
    }
    CHECK(Decode("caf\xE9") == L"caf\xDCE9");
}

TEST_CASE("utf8 escape: a lone surrogate outside the stand-ins is written as U+FFFD")
{
    CHECK_BYTES(Encode(L"a\xD800" L"b"), "a\xEF\xBF\xBD" "b");
    CHECK_BYTES(Encode(L"\xDC10"), "\xEF\xBF\xBD");
}

TEST_CASE("property: every byte string survives decode and encode")
{
    test::Rng rng(0x5C5Cull);
    for (int i = 0; i < 20000; ++i) {
        std::string s(rng.Below(24), '\0');
        for (auto& c : s)
            c = static_cast<char>(rng.Below(256));
        CHECK(Encode(Decode(s)) == s);
    }
}
