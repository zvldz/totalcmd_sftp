#include "Test.h"
#include "global.h"
#include "SftpClient.h"
#include "ImportIoUtil.h"
#include "IExternalSessionSource.h"
#include "OpenSshAdapter.h"
#include "FileZillaAdapter.h"
#include "KittyAdapter.h"
#include "SecureCrtAdapter.h"

#include <windows.h>
#include <algorithm>
#include <array>
#include <fstream>
#include <string>
#include <vector>

namespace {

// A fresh folder in the temporary folder, removed with what is in it when
// the test ends.
struct TempDir {
    std::string path;
    explicit TempDir(const char* tag)
    {
        std::array<char, MAX_PATH> dir{};
        GetTempPathA(static_cast<DWORD>(dir.size()), dir.data());
        path = std::string(dir.data()) + "sftpplug-unit-" + tag + "-" + std::to_string(GetCurrentProcessId());
        Remove(path);
        CreateDirectoryA(path.c_str(), nullptr);
    }
    ~TempDir() { Remove(path); }
    std::string File(const std::string& name, const std::string& bytes) const
    {
        const std::string p = path + "\\" + name;
        std::ofstream out(p, std::ios::binary | std::ios::trunc);
        out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        return p;
    }
    std::string Dir(const std::string& name) const
    {
        const std::string p = path + "\\" + name;
        CreateDirectoryA(p.c_str(), nullptr);
        return p;
    }
    static void Remove(const std::string& dir)
    {
        WIN32_FIND_DATAA fd{};
        HANDLE h = FindFirstFileA((dir + "\\*").c_str(), &fd);
        if (h != INVALID_HANDLE_VALUE) {
            do {
                const std::string name = fd.cFileName;
                if (name == "." || name == "..")
                    continue;
                const std::string p = dir + "\\" + name;
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                    Remove(p);
                else
                    DeleteFileA(p.c_str());
            } while (FindNextFileA(h, &fd));
            FindClose(h);
        }
        RemoveDirectoryA(dir.c_str());
    }
};

std::vector<std::string> Names(const sftp::EnumerationResult& r)
{
    std::vector<std::string> names;
    for (const auto& e : r.sessions)
        names.push_back(e.displayName);
    return names;
}

bool Has(const std::vector<std::string>& names, const char* name)
{
    return std::find(names.begin(), names.end(), name) != names.end();
}

struct Loaded {
    bool ok = false;
    tConnectSettings settings;
    sftp::SessionDependency dependency;
};

void Load(sftp::IExternalSessionSource& source, const std::string& origin, const char* name, Loaded& out)
{
    sftp::ExternalSessionEntry entry;
    entry.displayName = name;
    entry.sourceOrigin = origin;
    out.ok = source.LoadSettings(entry, &out.settings, &out.dependency);
}

} // namespace

TEST_CASE("import: server and port composed, IPv6 in brackets")
{
    CHECK_EQ(sftp::ComposeServer("host", 22), std::string("host"));
    CHECK_EQ(sftp::ComposeServer("host", 0), std::string("host"));
    CHECK_EQ(sftp::ComposeServer("host", 2222), std::string("host:2222"));
    CHECK_EQ(sftp::ComposeServer("fe80::1", 2222), std::string("[fe80::1]:2222"));
    CHECK_EQ(sftp::ComposeServer("fe80::1", 22), std::string("fe80::1"));
    CHECK_EQ(sftp::ComposeServer("[fe80::1]", 2222), std::string("[fe80::1]:2222"));
    CHECK_EQ(sftp::ComposeServer("", 2222), std::string(""));
}

TEST_CASE("import: code page names")
{
    int utf8 = -1, cp = -1;
    CHECK(sftp::ParseLineCodePage("UTF-8", utf8, cp));
    CHECK(utf8 == 1 && cp == 0);
    CHECK(sftp::ParseLineCodePage(" utf8 ", utf8, cp));
    CHECK(utf8 == 1);
    CHECK(sftp::ParseLineCodePage("CP65001", utf8, cp));
    CHECK(utf8 == 1 && cp == 0);
    CHECK(sftp::ParseLineCodePage("KOI8-R", utf8, cp));
    CHECK(utf8 == 0 && cp == 20866);
    CHECK(sftp::ParseLineCodePage("KOI8-U", utf8, cp));
    CHECK(cp == 21866);
    CHECK(sftp::ParseLineCodePage("ISO-8859-2", utf8, cp));
    CHECK(cp == 28592);
    CHECK(sftp::ParseLineCodePage("ISO-8859-15", utf8, cp));
    CHECK(cp == 28605);
    CHECK(sftp::ParseLineCodePage("CP1251", utf8, cp));
    CHECK(cp == 1251);
    CHECK(sftp::ParseLineCodePage("Windows-1250", utf8, cp));
    CHECK(cp == 1250);
    CHECK(sftp::ParseLineCodePage("WIN-1252", utf8, cp));
    CHECK(cp == 1252);
    CHECK(sftp::ParseLineCodePage("866", utf8, cp));
    CHECK(cp == 866);
    CHECK(!sftp::ParseLineCodePage("", utf8, cp));
    CHECK(!sftp::ParseLineCodePage("Use font encoding", utf8, cp));
    CHECK(!sftp::ParseLineCodePage("CP12x", utf8, cp));
}

TEST_CASE("import: PuTTY name encoding round trip")
{
    CHECK_EQ(sftp::PuttyUrlEncode("my server"), std::string("my%20server"));
    CHECK_EQ(sftp::PuttyUrlEncode(".hidden"), std::string("%2Ehidden"));
    CHECK_EQ(sftp::PuttyUrlEncode("a.b(c)@d"), std::string("a.b(c)@d"));
    CHECK_EQ(sftp::PuttyUrlEncode("50%*?\\"), std::string("50%25%2A%3F%5C"));
    CHECK_EQ(sftp::PuttyUrlDecode("my%20server"), std::string("my server"));
    CHECK_EQ(sftp::PuttyUrlDecode("100%"), std::string("100%"));
    CHECK_EQ(sftp::PuttyUrlDecode("%zz%4"), std::string("%zz%4"));
    std::string all;
    for (int i = 1; i < 256; ++i)
        all.push_back(static_cast<char>(i));
    CHECK_BYTES(sftp::PuttyUrlDecode(sftp::PuttyUrlEncode(all)), all);
}

TEST_CASE("import: a session file name stays below its folder")
{
    CHECK(sftp::IsNameBelowRoot("web"));
    CHECK(sftp::IsNameBelowRoot("folder/web"));
    CHECK(sftp::IsNameBelowRoot("folder\\web"));
    CHECK(sftp::IsNameBelowRoot("..web"));
    CHECK(sftp::IsNameBelowRoot("a/...b"));
    CHECK(!sftp::IsNameBelowRoot(""));
    CHECK(!sftp::IsNameBelowRoot(".."));
    CHECK(!sftp::IsNameBelowRoot("../web"));
    CHECK(!sftp::IsNameBelowRoot("a/../../web"));
    CHECK(!sftp::IsNameBelowRoot("a\\..\\web"));
    CHECK(!sftp::IsNameBelowRoot("a/.."));
    CHECK(!sftp::IsNameBelowRoot("\\web"));
    CHECK(!sftp::IsNameBelowRoot("/web"));
    CHECK(!sftp::IsNameBelowRoot("C:web"));
    CHECK(!sftp::IsNameBelowRoot("C:\\Windows\\web"));
}

TEST_CASE("openssh: hosts listed once, patterns left out")
{
    TempDir dir("openssh-list");
    const std::string config = dir.File("config",
        "Host *\n"
        "  ServerAliveInterval 30\n"
        "Host web web.lan\n"
        "  HostName 10.0.0.5\n"
        "Host db?  !bad Web\n"
        "  Port 2222\n");
    sftp::OpenSshAdapter adapter;
    const auto names = Names(adapter.EnumerateCustomPath(config));
    CHECK_EQ(names.size(), size_t(2));
    CHECK(Has(names, "web"));
    CHECK(Has(names, "web.lan"));
}

TEST_CASE("openssh: first value wins, Include and Match apply")
{
    TempDir dir("openssh-resolve");
    const std::string inc = dir.File("extra.conf",
        "Host web\n"
        "  User fromInclude\n"
        "  Port 2200\n");
    const std::string config = dir.File("config",
        "Host web\n"
        "  HostName 10.0.0.5\n"
        "  Include " + inc + "\n"
        "Match host 10.0.0.5\n"
        "  IdentityFile C:\\keys\\matched\n"
        "Host web\n"
        "  HostName ignored.example\n"
        "  User ignored\n");
    sftp::OpenSshAdapter adapter;
    Loaded l;
    Load(adapter, config, "web", l);
    CHECK(l.ok);
    CHECK_EQ(l.settings.server, std::string("10.0.0.5:2200"));
    CHECK_EQ(l.settings.user, std::string("fromInclude"));
    CHECK_EQ(l.settings.privkeyfile, std::string("C:\\keys\\matched"));
    CHECK(!l.dependency.blocks());
}

TEST_CASE("openssh: an Include in a block that does not apply brings nothing")
{
    TempDir dir("openssh-inactive");
    const std::string inc = dir.File("other.conf",
        "Host *\n"
        "  User leaked\n");
    const std::string config = dir.File("config",
        "Host other\n"
        "  Include " + inc + "\n"
        "Host web\n"
        "  HostName web.example\n"
        "  User right\n");
    sftp::OpenSshAdapter adapter;
    Loaded l;
    Load(adapter, config, "web", l);
    CHECK(l.ok);
    CHECK_EQ(l.settings.user, std::string("right"));
}

TEST_CASE("openssh: an Include that includes itself stops")
{
    TempDir dir("openssh-loop");
    const std::string config = dir.path + "\\config";
    dir.File("config",
        "Include " + config + "\n"
        "Host web\n"
        "  HostName web.example\n");
    sftp::OpenSshAdapter adapter;
    Loaded l;
    Load(adapter, config, "web", l);
    CHECK(l.ok);
    CHECK_EQ(l.settings.server, std::string("web.example"));
}

TEST_CASE("openssh: a route in a Match that cannot be told is refused")
{
    TempDir dir("openssh-match");
    const std::string config = dir.File("config",
        "Match exec \"test -f /x\"\n"
        "  ProxyJump bastion\n"
        "Host web\n"
        "  HostName web.example\n");
    sftp::OpenSshAdapter adapter;
    Loaded l;
    Load(adapter, config, "web", l);
    CHECK(l.ok);
    CHECK(l.dependency.blocks());
    CHECK(l.dependency.kind == sftp::SessionDependency::Kind::Bastion);
}

TEST_CASE("openssh: one ProxyJump hop becomes the jump host")
{
    TempDir dir("openssh-jump");
    const std::string config = dir.File("config",
        "Host bastion\n"
        "  HostName jump.example\n"
        "  User jumper\n"
        "  Port 2022\n"
        "Host web\n"
        "  HostName web.example\n"
        "  ProxyJump bastion\n"
        "Host chain\n"
        "  ProxyJump a,b\n"
        "Host cmd\n"
        "  ProxyCommand nc %h %p\n");
    sftp::OpenSshAdapter adapter;
    Loaded l;
    Load(adapter, config, "web", l);
    CHECK(l.ok);
    CHECK(!l.dependency.blocks());
    CHECK(l.settings.use_jump_host);
    CHECK_EQ(l.settings.jump_host, std::string("jump.example"));
    CHECK_EQ(l.settings.jump_user, std::string("jumper"));
    CHECK_EQ(int(l.settings.jump_port), 2022);

    Loaded chain;
    Load(adapter, config, "chain", chain);
    CHECK(chain.dependency.blocks());
    Loaded cmd;
    Load(adapter, config, "cmd", cmd);
    CHECK(cmd.dependency.blocks());
}

TEST_CASE("filezilla: sites with one name stay apart, other protocols are left out")
{
    TempDir dir("filezilla");
    const std::string xml = dir.File("sitemanager.xml",
        "\xEF\xBB\xBF<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<FileZilla3><Servers>\n"
        "<Server><Host>one.example</Host><Port>22</Port><Protocol>1</Protocol><Name>web</Name></Server>\n"
        "<Server><Host>two.example</Host><Port>2222</Port><Protocol>1</Protocol><Name>Web</Name></Server>\n"
        "<Server><Host>three.example</Host><Protocol>1</Protocol><Name>web (2)</Name></Server>\n"
        "<Server><Host>ftp.example</Host><Protocol>0</Protocol><Name>ftp</Name></Server>\n"
        "<Folder>Team<Server><Host>fe80::1</Host><Port>2200</Port><Protocol>1</Protocol>"
        "<User>me</User><Name>v6 &amp; more</Name></Server></Folder>\n"
        "</Servers></FileZilla3>\n");
    sftp::FileZillaAdapter adapter;
    const auto names = Names(adapter.EnumerateCustomPath(xml));
    CHECK_EQ(names.size(), size_t(4));
    CHECK(Has(names, "web"));
    CHECK(Has(names, "Web (2)"));
    CHECK(Has(names, "web (2) (2)"));
    CHECK(Has(names, "Team/v6 & more"));
    CHECK(!Has(names, "ftp"));

    Loaded second;
    Load(adapter, xml, "Web (2)", second);
    CHECK(second.ok);
    CHECK_EQ(second.settings.server, std::string("two.example:2222"));

    Loaded v6;
    Load(adapter, xml, "Team/v6 & more", v6);
    CHECK(v6.ok);
    CHECK_EQ(v6.settings.server, std::string("[fe80::1]:2200"));
    CHECK_EQ(v6.settings.user, std::string("me"));
}

TEST_CASE("kitty: session files read, templates and other protocols left out")
{
    TempDir dir("kitty");
    const std::string sessions = dir.Dir("Sessions");
    dir.File("Sessions\\my%20web",
        "HostName\\web.example\\\r\n"
        "PortNumber\\2222\\\r\n"
        "Protocol\\ssh\\\r\n"
        "UserName\\deploy\\\r\n"
        "LineCodePage\\KOI8-R\\\r\n"
        "TryAgent\\0\\\r\n"
        "PublicKeyFile\\C:%5Ckeys%5Cid.ppk\\\r\n");
    dir.File("Sessions\\telnet",
        "HostName\\old.example\\\r\n"
        "Protocol\\telnet\\\r\n");
    dir.File("Sessions\\Default%20Settings",
        "HostName\\\\\r\n"
        "Protocol\\ssh\\\r\n");
    sftp::KittyAdapter adapter;
    const auto names = Names(adapter.EnumerateCustomPath(dir.path));
    CHECK_EQ(names.size(), size_t(1));
    CHECK(Has(names, "my web"));

    Loaded l;
    Load(adapter, dir.path, "my web", l);
    CHECK(l.ok);
    CHECK_EQ(l.settings.server, std::string("web.example:2222"));
    CHECK_EQ(l.settings.user, std::string("deploy"));
    CHECK_EQ(l.settings.privkeyfile, std::string("C:\\keys\\id.ppk"));
    CHECK_EQ(l.settings.codepage, 20866);
    CHECK(!l.settings.useagent);
    CHECK(l.settings.password.empty());
    (void)sessions;
}
