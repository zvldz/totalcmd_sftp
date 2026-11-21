// LngLoader.cpp — loads external language\XX.lng translation files at runtime.
//
// File format (UTF-8, one entry per line):
//   ID=text
// where ID is the numeric resource id, and text uses RC-style escape sequences:
//   \n  \r  \t  \\
// Lines starting with # are comments; blank lines are ignored.
//
// Deployment layout (inside the plugin ZIP / install dir):
//   language\pol.lng   (Polish)
//   language\deu.lng   (German)
//   language\fra.lng   (French)
//   language\esp.lng   (Spanish)
//   language\ita.lng   (Italian)
//   language\rus.lng   (Russian)
//   language\cs.lng    (Czech)
//   language\hu.lng    (Hungarian)
//   language\ja.lng    (Japanese)
//   language\nl.lng    (Dutch)
//   language\pt-br.lng (Portuguese — Brazil)
//   language\ro.lng    (Romanian)
//   language\sk.lng    (Slovak)
//   language\uk.lng    (Ukrainian)
//   language\zh-cn.lng (Chinese Simplified)

#include <windows.h>
#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>
#include <array>
#include "LngLoader.h"

using LngMap = std::unordered_map<UINT, std::string>;

// The translation in use: resource id -> UTF-8 text; null = built-in
// English. Any thread reads it without a lock and keeps pointers into it,
// so a published map is never changed or freed: switching the language
// publishes a new map and keeps the earlier ones (a few per session) until
// the plugin is unloaded.
static std::atomic<const LngMap*> g_lngMap{nullptr};
static std::mutex g_lngLoadMutex;                    // serialises loads
static std::vector<std::unique_ptr<LngMap>> g_lngMaps;  // every map loaded
static std::wstring g_lngLoadedPath;                 // file of g_lngMap; "" = none

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

static std::string UnescapeRcString(const std::string& raw)
{
    std::string out;
    out.reserve(raw.size());
    for (size_t i = 0; i < raw.size(); ++i) {
        if (raw[i] == '\\' && i + 1 < raw.size()) {
            switch (raw[i + 1]) {
            case 'n':  out += '\n'; ++i; break;
            case 'r':  out += '\r'; ++i; break;
            case 't':  out += '\t'; ++i; break;
            case '\\': out += '\\'; ++i; break;
            default:   out += raw[i]; break;
            }
        } else {
            out += raw[i];
        }
    }
    return out;
}

static bool ParseLngLine(const std::string& line, UINT& outId, std::string& outText)
{
    if (line.empty() || line[0] == '#')
        return false;

    const size_t eq = line.find('=');
    if (eq == std::string::npos || eq == 0)
        return false;

    char* endPtr = nullptr;
    const unsigned long id = strtoul(line.c_str(), &endPtr, 10);
    if (endPtr != line.c_str() + eq)
        return false;

    outId   = static_cast<UINT>(id);
    outText = UnescapeRcString(line.substr(eq + 1));
    return true;
}

// Map LANGID to the lng filename stem used in language\XX.lng filenames.
// Simple 3-letter codes match TC's own .LNG stems (WCMD_POL.LNG → "pol").
// Languages with multiple regional variants are handled before the switch.
static const char* LangIdToTcCode(LANGID id) noexcept
{
    // Sublanguage disambiguation for Portuguese and Chinese
    if (PRIMARYLANGID(id) == LANG_PORTUGUESE)
        return (SUBLANGID(id) == SUBLANG_PORTUGUESE_BRAZILIAN) ? "pt-br" : nullptr;
    if (PRIMARYLANGID(id) == LANG_CHINESE)
        return (SUBLANGID(id) == SUBLANG_CHINESE_SIMPLIFIED)   ? "zh-cn" : nullptr;

    switch (PRIMARYLANGID(id)) {
    case LANG_POLISH:     return "pol";
    case LANG_GERMAN:     return "deu";
    case LANG_FRENCH:     return "fra";
    case LANG_SPANISH:    return "esp";
    case LANG_ITALIAN:    return "ita";
    case LANG_RUSSIAN:    return "rus";
    case LANG_CZECH:      return "cs";
    case LANG_HUNGARIAN:  return "hu";
    case LANG_JAPANESE:   return "ja";
    case LANG_DUTCH:      return "nl";
    case LANG_ROMANIAN:   return "ro";
    case LANG_SLOVAK:     return "sk";
    case LANG_UKRAINIAN:  return "uk";
    default:              return nullptr;
    }
}

// ---------------------------------------------------------------------------
// Internal file loader
// ---------------------------------------------------------------------------

static void LoadLngFromPath(const std::wstring& lngPath, LngMap& map) noexcept
{
    HANDLE hFile = CreateFileW(lngPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
        return;

    const DWORD fileSize = GetFileSize(hFile, nullptr);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
        CloseHandle(hFile);
        return;
    }

    std::string content(fileSize, '\0');
    DWORD bytesRead = 0;
    const BOOL ok = ReadFile(hFile, content.data(), fileSize, &bytesRead, nullptr);
    CloseHandle(hFile);
    if (!ok)
        return;
    content.resize(bytesRead);

    // Strip UTF-8 BOM if present
    if (content.size() >= 3 &&
        static_cast<unsigned char>(content[0]) == 0xEF &&
        static_cast<unsigned char>(content[1]) == 0xBB &&
        static_cast<unsigned char>(content[2]) == 0xBF)
    {
        content.erase(0, 3);
    }

    // Parse line by line (handle both CRLF and LF)
    size_t pos = 0;
    while (pos < content.size()) {
        size_t end = content.find('\n', pos);
        if (end == std::string::npos)
            end = content.size();

        std::string line = content.substr(pos, end - pos);
        if (!line.empty() && line.back() == '\r')
            line.pop_back();

        UINT id = 0;
        std::string text;
        if (ParseLngLine(line, id, text))
            map.emplace(id, std::move(text));

        pos = end + 1;
    }
}

// The language folder beside the plugin, as a wide path: the plugin may sit
// in a folder whose name the system codepage cannot spell.
static std::wstring GetPluginLangDir(HINSTANCE hPluginInst) noexcept
{
    try {
        std::vector<wchar_t> dllPath(32768);
        const DWORD n = GetModuleFileNameW(hPluginInst, dllPath.data(),
                                           static_cast<DWORD>(dllPath.size()));
        if (n == 0 || n >= dllPath.size())
            return {};
        std::wstring dir(dllPath.data(), n);
        const size_t lastSlash = dir.find_last_of(L'\\');
        if (lastSlash == std::wstring::npos)
            return {};
        dir.resize(lastSlash + 1);
        return dir + L"language\\";
    } catch (...) {
        return {};
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// Publishes the translation in `lngPath` ("" = built-in English). The same
// file is not loaded again, so calling this on every root listing is cheap.
static void PublishLanguage(const std::wstring& lngPath) noexcept
{
    std::lock_guard<std::mutex> lock(g_lngLoadMutex);
    if (lngPath == g_lngLoadedPath)
        return;
    g_lngLoadedPath = lngPath;
    if (lngPath.empty()) {
        g_lngMap.store(nullptr);
        return;
    }
    try {
        auto map = std::make_unique<LngMap>();
        LoadLngFromPath(lngPath, *map);
        g_lngMap.store(map.get());
        g_lngMaps.push_back(std::move(map));
    } catch (...) {
        g_lngMap.store(nullptr);
    }
}

static std::wstring LngPathForCode(const char* code, HINSTANCE hPluginInst) noexcept
{
    if (!code || !code[0])
        return {};
    const std::wstring dir = GetPluginLangDir(hPluginInst);
    if (dir.empty())
        return {};
    // Language codes are ASCII ("rus", "pt-br").
    std::wstring path = dir;
    for (const char* p = code; *p; ++p)
        path += static_cast<wchar_t>(static_cast<unsigned char>(*p));
    return path + L".lng";
}

void LngLoadForLanguage(LANGID langId, HINSTANCE hPluginInst) noexcept
{
    // English or a language without a .lng: the built-in RC strings.
    PublishLanguage(LngPathForCode(LangIdToTcCode(langId), hPluginInst));
}

void LngLoadByCode(const char* code, HINSTANCE hPluginInst) noexcept
{
    PublishLanguage(LngPathForCode(code, hPluginInst));
}

std::vector<std::string> LngAllTranslations(UINT id, HINSTANCE hPluginInst) noexcept
{
    // Every .lng beside the plugin, read once: shipped and custom files
    // alike, whatever the language in use.
    static std::once_flag once;
    static std::vector<LngMap> all;
    std::call_once(once, [&]() noexcept {
        try {
            const std::wstring dir = GetPluginLangDir(hPluginInst);
            if (dir.empty())
                return;
            WIN32_FIND_DATAW fd{};
            HANDLE h = FindFirstFileW((dir + L"*.lng").c_str(), &fd);
            if (h == INVALID_HANDLE_VALUE)
                return;
            do {
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                    continue;
                LngMap map;
                LoadLngFromPath(dir + fd.cFileName, map);
                all.push_back(std::move(map));
            } while (FindNextFileW(h, &fd));
            FindClose(h);
        } catch (...) {
        }
    });
    std::vector<std::string> out;
    try {
        for (const LngMap& map : all) {
            const auto it = map.find(id);
            if (it != map.end())
                out.push_back(it->second);
        }
    } catch (...) {
    }
    return out;
}

const char* LngGetString(UINT id) noexcept
{
    const LngMap* map = g_lngMap.load();
    if (!map)
        return nullptr;
    const auto it = map->find(id);
    if (it == map->end())
        return nullptr;
    return it->second.c_str();
}

bool LngLoadStringW(HINSTANCE hInst, UINT id, WCHAR* buf, int bufLen) noexcept
{
    if (!buf || bufLen <= 0)
        return false;
    const char* utf8 = LngGetString(id);
    if (utf8) {
        int n = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, buf, bufLen);
        return n > 0;
    }
    return LoadStringW(hInst, id, buf, bufLen) > 0;
}
