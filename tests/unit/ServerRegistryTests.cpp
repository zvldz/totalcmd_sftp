#include "Test.h"
#include "global.h"
#include "ServerRegistry.h"
#include "IniFile.h"

#include <windows.h>
#include <array>
#include <string>

namespace {

// The registry holds the sessions of one INI file at a time: each test loads
// its own, and an empty one when it ends.
struct TempRegistry {
    std::wstring path;
    explicit TempRegistry(const wchar_t* tag)
    {
        std::array<wchar_t, MAX_PATH> dir{};
        GetTempPathW(static_cast<DWORD>(dir.size()), dir.data());
        path = std::wstring(dir.data()) + L"sftpplug-unit-" + tag + L"-" + std::to_wstring(GetCurrentProcessId()) + L".ini";
        DeleteFileW(path.c_str());
    }
    ~TempRegistry()
    {
        DeleteFileW(path.c_str());
        LoadServersFromIniW(path.c_str(), nullptr);
    }
    void Session(const wchar_t* name) const { IniWriteString(name, L"server", L"host", path.c_str()); }
    void Load() const { LoadServersFromIniW(path.c_str(), nullptr); }
};

} // namespace

TEST_CASE("registry: session names that cannot be used")
{
    TempRegistry reg(L"names");
    reg.Session(L"web");
    reg.Session(L"team/db");
    reg.Load();

    CHECK(IsUsableSessionName("new"));
    CHECK(IsUsableSessionName("team/new"));
    CHECK(IsUsableSessionName("a/b/c"));
    CHECK(!IsUsableSessionName(""));
    CHECK(!IsUsableSessionName(" lead"));
    CHECK(!IsUsableSessionName("trail "));
    CHECK(!IsUsableSessionName("[Imports]"));
    CHECK(!IsUsableSessionName("__vimp_x"));
    CHECK(!IsUsableSessionName("a$$b"));
    CHECK(!IsUsableSessionName("tab\there"));
    CHECK(!IsUsableSessionName("back\\slash"));
    CHECK(!IsUsableSessionName("Configuration"));
    CHECK(!IsUsableSessionName("imports"));
    CHECK(!IsUsableSessionName("proxy"));
    CHECK(!IsUsableSessionName("Proxy12"));
    CHECK(IsUsableSessionName("proxy-web"));
    CHECK(!IsUsableSessionName("a//b"));
    CHECK(!IsUsableSessionName("a/./b"));
    CHECK(!IsUsableSessionName("a/../b"));
    CHECK(!IsUsableSessionName("a/"));
    // Below an existing session, or in place of a folder that holds one.
    CHECK(!IsUsableSessionName("web/sub"));
    CHECK(!IsUsableSessionName("WEB/sub"));
    CHECK(!IsUsableSessionName("team"));
}

TEST_CASE("registry: a panel path resolves to a session, a folder or nothing")
{
    TempRegistry reg(L"paths");
    reg.Session(L"web");
    reg.Session(L"team/db");
    reg.Load();

    PathResolution r = ResolvePathKind("\\");
    CHECK(r.kind == PathKind::Folder);
    CHECK(r.displayName.empty());

    r = ResolvePathKind("\\web");
    CHECK(r.kind == PathKind::SessionLeaf);
    CHECK_EQ(r.displayName, std::string("web"));

    r = ResolvePathKind("\\WEB\\var\\log");
    CHECK(r.kind == PathKind::SessionWithSubpath);
    CHECK_EQ(r.displayName, std::string("web"));
    CHECK_EQ(r.relative, std::string("\\var\\log"));

    r = ResolvePathKind("\\team");
    CHECK(r.kind == PathKind::Folder);
    CHECK_EQ(r.displayName, std::string("team"));

    r = ResolvePathKind("\\team\\");
    CHECK(r.kind == PathKind::Folder);

    r = ResolvePathKind("\\team\\db\\etc");
    CHECK(r.kind == PathKind::SessionWithSubpath);
    CHECK_EQ(r.displayName, std::string("team/db"));
    CHECK_EQ(r.relative, std::string("\\etc"));

    r = ResolvePathKind("\\nothing");
    CHECK(r.kind == PathKind::Invalid);
    r = ResolvePathKind("\\te");
    CHECK(r.kind == PathKind::Invalid);
}
