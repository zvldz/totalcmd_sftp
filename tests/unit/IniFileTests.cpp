#include "Test.h"
#include "IniFile.h"

#include <windows.h>
#include <array>
#include <fstream>
#include <string>
#include <vector>

namespace {

// A fresh INI file in the temporary folder, removed when the test ends.
struct TempIni {
    std::wstring path;
    explicit TempIni(const wchar_t* tag)
    {
        std::array<wchar_t, MAX_PATH> dir{};
        GetTempPathW(static_cast<DWORD>(dir.size()), dir.data());
        path = std::wstring(dir.data()) + L"sftpplug-unit-" + tag + L"-" + std::to_wstring(GetCurrentProcessId()) + L".ini";
        DeleteFileW(path.c_str());
    }
    ~TempIni() { DeleteFileW(path.c_str()); }
    void WriteBytes(const std::string& bytes) const
    {
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    }
};

std::wstring Get(const wchar_t* section, const wchar_t* key, const std::wstring& path, DWORD size = 4096)
{
    std::vector<wchar_t> buf(size);
    IniGetString(section, key, L"", buf.data(), size, path.c_str());
    return buf.data();
}

} // namespace

TEST_CASE("ini: a value written is read back")
{
    TempIni ini(L"roundtrip");
    CHECK(IniWriteString(L"session", L"server", L"host:2222", ini.path.c_str()));
    CHECK(Get(L"session", L"server", ini.path) == L"host:2222");
    CHECK(Get(L"SESSION", L"SERVER", ini.path) == L"host:2222");
    CHECK(IniWriteString(L"session", L"server", nullptr, ini.path.c_str()));
    CHECK(Get(L"session", L"server", ini.path).empty());
}

TEST_CASE("ini: a section name with brackets is kept whole")
{
    TempIni ini(L"brackets");
    CHECK(IniWriteString(L"web [old]", L"user", L"tester", ini.path.c_str()));
    CHECK(Get(L"web [old]", L"user", ini.path) == L"tester");
    bool listed = false;
    for (const std::string& name : IniSectionNameList(ini.path.c_str()))
        listed = listed || name == "web [old]";
    CHECK(listed);
}

TEST_CASE("ini: a line break in a value or name is refused")
{
    TempIni ini(L"crlf");
    CHECK(!IniWriteString(L"s", L"k", L"one\r\n[injected]", ini.path.c_str()));
    CHECK(!IniWriteString(L"s\nx", L"k", L"v", ini.path.c_str()));
    CHECK(Get(L"injected", nullptr, ini.path).empty());
}

TEST_CASE("ini: a value in quotes comes back with its quotes")
{
    TempIni ini(L"quotes");
    const wchar_t* value = L"\"/usr/lib/sftp-server\" -l INFO";
    CHECK(IniWriteString(L"s", L"cmd", value, ini.path.c_str()));
    CHECK(Get(L"s", L"cmd", ini.path) == value);
    CHECK(IniWriteString(L"s", L"quoted", L"\"x\"", ini.path.c_str()));
    CHECK(Get(L"s", L"quoted", ini.path) == L"\"x\"");
}

TEST_CASE("ini: a long value is read whole, a short buffer cuts it like the profile API")
{
    TempIni ini(L"long");
    const std::wstring longValue(5000, L'a');
    CHECK(IniWriteString(L"s", L"k", longValue.c_str(), ini.path.c_str()));
    CHECK(Get(L"s", L"k", ini.path, 8192) == longValue);
    std::array<wchar_t, 16> small{};
    const DWORD got = IniGetString(L"s", L"k", L"", small.data(), static_cast<DWORD>(small.size()), ini.path.c_str());
    CHECK(got == small.size() - 1);
}

TEST_CASE("ini: many sections are all listed")
{
    TempIni ini(L"many");
    for (int i = 0; i < 3000; ++i) {
        const std::wstring name = L"session-with-a-fairly-long-name-" + std::to_wstring(i);
        IniWriteString(name.c_str(), L"server", L"h", ini.path.c_str());
    }
    CHECK(IniSectionNameList(ini.path.c_str()).size() == 3000);
}

TEST_CASE("ini: one stray byte does not turn the rest of a UTF-8 file into ANSI")
{
    TempIni ini(L"mixed");
    // A Cyrillic section in UTF-8, and elsewhere one byte that is not UTF-8.
    ini.WriteBytes("[\xD1\x81\xD0\xB5\xD1\x80\xD0\xB2\xD0\xB5\xD1\x80]\r\nuser=tester\r\n"
                   "[other]\r\nnote=caf\xE9\r\n");
    CHECK(Get(L"\x0441\x0435\x0440\x0432\x0435\x0440", L"user", ini.path) == L"tester");
}
