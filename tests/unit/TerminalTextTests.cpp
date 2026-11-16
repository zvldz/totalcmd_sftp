#include "Test.h"
#include "TerminalText.h"

#include <string>

using terminal_text::DecodeLsEscapedName;
using terminal_text::StripControls;

TEST_CASE("terminal: systemd OSC 3008 context records terminated by ST")
{
    // Captured from an Ubuntu 26.04 bash prompt (systemd 257+).
    const std::string line =
        "\x1B]3008;end=cd65;exit=success\x1B\\"
        "\x1B]3008;start=dfb5;machineid=97b3;user=root;hostname=T14;type=shell;cwd=/root\x1B\\"
        "\x1B[?2004hroot@T14:~# __WFX_LIST_BEGIN___1";
    CHECK_BYTES(StripControls(line), "root@T14:~# __WFX_LIST_BEGIN___1");
}

TEST_CASE("terminal: CSI forms, titles and short escapes")
{
    CHECK_BYTES(StripControls("\x1B[01;34mdir\x1B[0m"), "dir");
    CHECK_BYTES(StripControls("\x1B[?2004l\rtext"), "\rtext");
    CHECK_BYTES(StripControls("\x1B]0;user@host: ~\x07prompt$ "), "prompt$ ");
    CHECK_BYTES(StripControls("a\x1B(Bb\x1B=c\x1B>d"), "abcd");
    CHECK_BYTES(StripControls("\x1BPq#0;2;0;0;0\x1B\\after"), "after");
    CHECK_BYTES(StripControls("bell\x07 rings"), "bell rings");
    CHECK_BYTES(StripControls("cut \x1B[38;5"), "cut ");
    CHECK_BYTES(StripControls("cut \x1B]0;never ends"), "cut ");
    CHECK_BYTES(StripControls("lone \x1B"), "lone ");
}

TEST_CASE("terminal: UTF-8 text survives, including bytes 0x80-0x9F")
{
    // U+0141 U+0105 U+0144 U+2713 U+0434 encode with continuation bytes in 0x80-0x9F.
    const std::string utf8 = "\xC5\x81\xC4\x85\xC5\x84 \xE2\x9C\x93 \xD0\xB4";
    CHECK_BYTES(StripControls("\x1B[1m" + utf8 + "\x1B[0m"), utf8);
}

TEST_CASE("terminal: backslashes in names are kept as they are")
{
    CHECK_BYTES(StripControls("a\\101b \\040 trail\\12"), "a\\101b \\040 trail\\12");
}

TEST_CASE("ls: escaped names decode to their bytes")
{
    // As GNU coreutils 9.7 prints them with LC_ALL=C QUOTING_STYLE=escape.
    CHECK_BYTES(DecodeLsEscapedName("a\\ b"), "a b");
    CHECK_BYTES(DecodeLsEscapedName("\\ lead"), " lead");
    CHECK_BYTES(DecodeLsEscapedName("trail\\ "), "trail ");
    CHECK_BYTES(DecodeLsEscapedName("back\\\\101slash"), "back\\101slash");
    CHECK_BYTES(DecodeLsEscapedName("nl\\nfake"), "nl\nfake");
    CHECK_BYTES(DecodeLsEscapedName("tab\\there"), "tab\there");
    CHECK_BYTES(DecodeLsEscapedName("arrow\\ ->\\ x"), "arrow -> x");
    CHECK_BYTES(DecodeLsEscapedName("q'uote"), "q'uote");
    CHECK_BYTES(DecodeLsEscapedName("\\320\\272\\320\\270\\321\\200"), "\xD0\xBA\xD0\xB8\xD1\x80");
    CHECK_BYTES(DecodeLsEscapedName("cut\\"), "cut\\");
}

TEST_CASE("property: stripped text never contains ESC and plain text is untouched")
{
    test::Rng rng(0x3008ull);
    static constexpr char alphabet[] = {'a', 'Z', ' ', '\x1B', '[', ']', '\\', '?', ';', '0', '9', 'm', 'h', '\x07', '(', 'B'};
    for (int i = 0; i < 20000; ++i) {
        std::string s(rng.Below(40), '\0');
        for (auto& c : s)
            c = alphabet[rng.Below(sizeof(alphabet))];
        const std::string out = StripControls(s);
        CHECK(out.find('\x1B') == std::string::npos);
        CHECK(out.size() <= s.size());
        if (s.find('\x1B') == std::string::npos && s.find('\x07') == std::string::npos)
            CHECK(out == s);
    }
}
