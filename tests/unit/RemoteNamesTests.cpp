#include "Test.h"
#include "RemoteNames.h"

#include <windows.h>
#include <string>

namespace {

SYSTEMTIME Date(const char* mon, const char* day, const char* timeOrYear, bool* ok)
{
    FILETIME ft{};
    SYSTEMTIME st{};
    *ok = ParseLsDate(mon, day, timeOrYear, ft) && FileTimeToSystemTime(&ft, &st);
    return st;
}

std::wstring Sanitized(const wchar_t* path)
{
    std::wstring s = path;
    SanitizeLocalFileNameW(s.data());
    return s;
}

} // namespace

TEST_CASE("ls: mode column to st_mode")
{
    CHECK_EQ(ParseLsMode("drwxr-xr-x"), DWORD(040755));
    CHECK_EQ(ParseLsMode("-rw-r--r--"), DWORD(0100644));
    CHECK_EQ(ParseLsMode("lrwxrwxrwx"), DWORD(0120777));
    CHECK_EQ(ParseLsMode("-rwsr-xr-x"), DWORD(0104755));
    CHECK_EQ(ParseLsMode("-rwSr--r--"), DWORD(0104644));
    CHECK_EQ(ParseLsMode("drwxrwsr-x"), DWORD(042775));
    CHECK_EQ(ParseLsMode("drwxrwxrwt"), DWORD(041777));
    CHECK_EQ(ParseLsMode("drwxrwxrwT"), DWORD(041776));
    CHECK_EQ(ParseLsMode("crw-rw----"), DWORD(020660));
    CHECK_EQ(ParseLsMode("brw-rw----"), DWORD(060660));
    CHECK_EQ(ParseLsMode("prw-------"), DWORD(010600));
    CHECK_EQ(ParseLsMode("srwxrwxrwx"), DWORD(0140777));
    CHECK_EQ(ParseLsMode("-rw-r--r--+"), DWORD(0100644));
    CHECK_EQ(ParseLsMode("-rw-r--r-"), DWORD(0));
    CHECK_EQ(ParseLsMode(""), DWORD(0));
}

TEST_CASE("ls: dates with a year")
{
    bool ok = false;
    SYSTEMTIME st = Date("Feb", "29", "2024", &ok);
    CHECK(ok);
    CHECK(st.wYear == 2024 && st.wMonth == 2 && st.wDay == 29);
    st = Date("dec", "31", "1999", &ok);
    CHECK(ok);
    CHECK(st.wYear == 1999 && st.wMonth == 12 && st.wDay == 31);

    Date("Feb", "29", "2023", &ok);
    CHECK(!ok);
    Date("Foo", "1", "2020", &ok);
    CHECK(!ok);
    Date("Jan", "0", "2020", &ok);
    CHECK(!ok);
    Date("Jan", "32", "2020", &ok);
    CHECK(!ok);
    Date("Jan", "1", "1600", &ok);
    CHECK(!ok);
}

TEST_CASE("ls: a time without a year is this year, or last year when it is ahead")
{
    SYSTEMTIME now{};
    GetSystemTime(&now);
    bool ok = false;
    SYSTEMTIME st = Date("Jan", "1", "00:00", &ok);
    CHECK(ok);
    CHECK_EQ(st.wYear, now.wYear);
    CHECK(st.wHour == 0 && st.wMinute == 0);

    // December 31st is more than a day ahead except on December 30th and 31st.
    st = Date("Dec", "31", "23:59", &ok);
    CHECK(ok);
    const bool endOfYear = now.wMonth == 12 && now.wDay >= 30;
    CHECK_EQ(st.wYear, endOfYear ? now.wYear : WORD(now.wYear - 1));

    Date("Jan", "1", "24:00", &ok);
    CHECK(!ok);
    Date("Jan", "1", "12:60", &ok);
    CHECK(!ok);
}

TEST_CASE("shell: commands with control bytes are not sent")
{
    CHECK(ShellCommandIsSafe("ls -la '/home/user'"));
    CHECK(ShellCommandIsSafe("rm 'a\nb'"));
    CHECK(ShellCommandIsSafe("cat '\xD1\x84\xD0\xB0\xD0\xB9\xD0\xBB'"));
    CHECK(ShellCommandIsSafe(""));
    CHECK(!ShellCommandIsSafe("rm 'a\rb'"));
    CHECK(!ShellCommandIsSafe("rm 'a\tb'"));
    CHECK(!ShellCommandIsSafe("rm 'a\x15'"));
    CHECK(!ShellCommandIsSafe("rm 'a\x03'"));
    CHECK(!ShellCommandIsSafe("rm 'a\x1B[0m'"));
    CHECK(!ShellCommandIsSafe("rm 'a\x7F'"));
    CHECK(!ShellCommandIsSafe(std::string_view("rm a\0b", 6)));
}

TEST_CASE("shell: the file name of a quoted path")
{
    CHECK_EQ(BaseNameFromPath("'/home/user/file.txt'"), std::string("file.txt"));
    CHECK_EQ(BaseNameFromPath("'/tmp/it'\\''s here.txt'"), std::string("it's here.txt"));
    CHECK_EQ(BaseNameFromPath("/plain/name"), std::string("name"));
    CHECK_EQ(BaseNameFromPath("'name'"), std::string("name"));
    CHECK_EQ(BaseNameFromPath(""), std::string("upload.bin"));
    CHECK_EQ(BaseNameFromPath("'/dir/'"), std::string("/dir/"));
}

TEST_CASE("local names: characters Windows refuses become '_'")
{
    CHECK(Sanitized(L"C:\\dl\\a<b>c:d\"e|f?g*h") == L"C:\\dl\\a_b_c_d_e_f_g_h");
    CHECK(Sanitized(L"C:\\dl\\tab\there") == L"C:\\dl\\tab_here");
    CHECK(Sanitized(L"C:\\dl\\report.") == L"C:\\dl\\report_");
    CHECK(Sanitized(L"C:\\dl\\report ") == L"C:\\dl\\report_");
    CHECK(Sanitized(L"C:\\d:l\\ok.txt") == L"C:\\d:l\\ok.txt");
    CHECK(Sanitized(L"C:\\dl\\") == L"C:\\dl\\");
    CHECK(Sanitized(L"name") == L"name");
}

TEST_CASE("local names: device names lose their last letter")
{
    CHECK(Sanitized(L"C:\\dl\\nul") == L"C:\\dl\\nu_");
    CHECK(Sanitized(L"C:\\dl\\CON.txt") == L"C:\\dl\\CO_.txt");
    CHECK(Sanitized(L"C:\\dl\\aux .log") == L"C:\\dl\\au_ .log");
    CHECK(Sanitized(L"C:\\dl\\com1") == L"C:\\dl\\com_");
    CHECK(Sanitized(L"C:\\dl\\LPT9.bin") == L"C:\\dl\\LPT_.bin");
    CHECK(Sanitized(L"C:\\dl\\conin$") == L"C:\\dl\\conin_");
    CHECK(Sanitized(L"C:\\dl\\com0") == L"C:\\dl\\com0");
    CHECK(Sanitized(L"C:\\dl\\com10") == L"C:\\dl\\com10");
    CHECK(Sanitized(L"C:\\dl\\console") == L"C:\\dl\\console");
    CHECK(Sanitized(L"C:\\dl\\nul.tar.gz") == L"C:\\dl\\nu_.tar.gz");
}
