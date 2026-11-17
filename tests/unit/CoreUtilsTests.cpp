#include "Test.h"
#include "global.h"
#include "CoreUtils.h"

#include <array>
#include <string>
#include <vector>

namespace {

struct Address {
    bool ok = false;
    std::string host;
    WORD port = 0;
};

Address Parse(const char* in, int defport = 22, size_t size = 256)
{
    Address a;
    std::vector<char> buf(size, '\0');
    a.ok = ParseAddress(in, buf.data(), buf.size(), &a.port, defport);
    if (a.ok)
        a.host = buf.data();
    return a;
}

std::string Encode(const std::string& data)
{
    std::array<char, 1024> out{};
    MimeEncodeData(data.data(), data.size(), out.data(), out.size());
    return out.data();
}

std::string Decode(const std::string& text)
{
    std::array<char, 1024> out{};
    const int n = MimeDecode(text.data(), text.size(), out.data(), out.size());
    return std::string(out.data(), n > 0 ? static_cast<size_t>(n) : 0);
}

} // namespace

TEST_CASE("address: host, host:port and the default port")
{
    Address a = Parse("example.com");
    CHECK(a.ok);
    CHECK_EQ(a.host, std::string("example.com"));
    CHECK_EQ(a.port, WORD(22));

    a = Parse("  example.com:2222  ");
    CHECK(a.ok);
    CHECK_EQ(a.host, std::string("example.com"));
    CHECK_EQ(a.port, WORD(2222));

    a = Parse("10.0.0.1", 8022);
    CHECK(a.ok);
    CHECK_EQ(a.port, WORD(8022));
}

TEST_CASE("address: scheme, user and path are dropped")
{
    Address a = Parse("sftp://user@example.com:2200/home/user?x#y");
    CHECK(a.ok);
    CHECK_EQ(a.host, std::string("example.com"));
    CHECK_EQ(a.port, WORD(2200));

    // The last '@' separates the user, which may hold one itself.
    a = Parse("me@corp@host.lan");
    CHECK(a.ok);
    CHECK_EQ(a.host, std::string("host.lan"));
}

TEST_CASE("address: IPv6 with and without brackets")
{
    Address a = Parse("[fe80::1]:2222");
    CHECK(a.ok);
    CHECK_EQ(a.host, std::string("fe80::1"));
    CHECK_EQ(a.port, WORD(2222));

    a = Parse("[::1]");
    CHECK(a.ok);
    CHECK_EQ(a.host, std::string("::1"));
    CHECK_EQ(a.port, WORD(22));

    // Without brackets every colon belongs to the address.
    a = Parse("2001:db8::5");
    CHECK(a.ok);
    CHECK_EQ(a.host, std::string("2001:db8::5"));
    CHECK_EQ(a.port, WORD(22));

    CHECK(IsNumericIPv6("2001:db8::5"));
    CHECK(!IsNumericIPv6("host:22"));
    CHECK(!IsNumericIPv6("host"));
}

TEST_CASE("address: bad ports and empty hosts are refused")
{
    CHECK(!Parse("").ok);
    CHECK(!Parse("   ").ok);
    CHECK(!Parse("host:").ok);
    CHECK(!Parse(":22").ok);
    CHECK(!Parse("host:0").ok);
    CHECK(!Parse("host:65536").ok);
    CHECK(!Parse("host:99999999999999999999").ok);
    CHECK(!Parse("host:22x").ok);
    CHECK(!Parse("[]:22").ok);
    CHECK(!Parse("[::1").ok);
    CHECK(!Parse("[::1]22").ok);
    CHECK(!Parse("[::1]:").ok);
    CHECK(!Parse("sftp://").ok);
    CHECK(Parse("host:65535").ok);
}

TEST_CASE("address: a host that does not fit is refused, not cut")
{
    CHECK(!Parse("abcdefghij", 22, 10).ok);
    CHECK(Parse("abcdefghi", 22, 10).ok);
}

TEST_CASE("base64: the RFC 4648 vectors both ways")
{
    const char* plain[] = {"", "f", "fo", "foo", "foob", "fooba", "foobar"};
    const char* coded[] = {"", "Zg==", "Zm8=", "Zm9v", "Zm9vYg==", "Zm9vYmE=", "Zm9vYmFy"};
    for (size_t i = 0; i < 7; ++i) {
        CHECK_BYTES(Encode(plain[i]), coded[i]);
        CHECK_BYTES(Decode(coded[i]), plain[i]);
    }
}

TEST_CASE("base64: every byte value survives, line breaks are skipped")
{
    std::string all;
    for (int i = 0; i < 256; ++i)
        all.push_back(static_cast<char>(i));
    const std::string coded = Encode(all);
    CHECK_BYTES(Decode(coded), all);

    std::string wrapped;
    for (size_t i = 0; i < coded.size(); ++i) {
        wrapped.push_back(coded[i]);
        if (i % 60 == 59)
            wrapped += "\r\n";
    }
    CHECK_BYTES(Decode(wrapped), all);
}

TEST_CASE("base64: decoding stops at the output size")
{
    std::array<char, 4> out{};
    const int n = MimeDecode("Zm9vYmFy", 8, out.data(), 3);
    CHECK_EQ(n, 3);
    CHECK_BYTES(std::string(out.data(), 3), "foo");
}
