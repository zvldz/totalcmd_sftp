#include "IniFile.h"

#include <algorithm>
#include <cstdio>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace {

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

std::wstring ToWide(std::string_view s, UINT cp)
{
    if (s.empty())
        return {};
    const int n = MultiByteToWideChar(cp, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (n <= 0)
        return {};
    std::wstring w(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(cp, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
    return w;
}

std::string FromWide(std::wstring_view w, UINT cp)
{
    if (w.empty())
        return {};
    const int n = WideCharToMultiByte(cp, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    if (n <= 0)
        return {};
    std::string s(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(cp, 0, w.data(), static_cast<int>(w.size()), s.data(), n, nullptr, nullptr);
    return s;
}

// Caller strings → UTF-8 used inside the parsed file.
std::string ToUtf8(LPCSTR s)  { return s ? FromWide(ToWide(s, CP_ACP), CP_UTF8) : std::string(); }
std::string ToUtf8(LPCWSTR s) { return s ? FromWide(s, CP_UTF8) : std::string(); }

// UTF-8 from the parsed file → caller strings.
void FromUtf8(std::string_view u, std::string& out)  { out = FromWide(ToWide(u, CP_UTF8), CP_ACP); }
void FromUtf8(std::string_view u, std::wstring& out) { out = ToWide(u, CP_UTF8); }

std::wstring PathOf(LPCSTR p)  { return p ? ToWide(p, CP_ACP) : std::wstring(); }
std::wstring PathOf(LPCWSTR p) { return p ? std::wstring(p) : std::wstring(); }

// File bytes → UTF-8 text. UTF-16 LE needs its BOM; anything that is not
// valid UTF-8 is a legacy file in the system codepage.
std::string DecodeFile(const std::string& raw)
{
    const auto byte = [&raw](size_t i) { return static_cast<unsigned char>(raw[i]); };
    if (raw.size() >= 2 && byte(0) == 0xFF && byte(1) == 0xFE) {
        const std::wstring_view w(reinterpret_cast<const wchar_t*>(raw.data() + 2),
                                  (raw.size() - 2) / sizeof(wchar_t));
        return FromWide(w, CP_UTF8);
    }
    std::string_view body(raw);
    if (body.size() >= 3 && byte(0) == 0xEF && byte(1) == 0xBB && byte(2) == 0xBF)
        return std::string(body.substr(3));
    if (body.empty())
        return {};
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, body.data(),
                            static_cast<int>(body.size()), nullptr, 0) > 0)
        return std::string(body);
    return FromWide(ToWide(body, CP_ACP), CP_UTF8);
}

// ---------------------------------------------------------------------------
// Line parsing
// ---------------------------------------------------------------------------

std::string_view Trim(std::string_view s)
{
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t'))
        s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r'))
        s.remove_suffix(1);
    return s;
}

// Name comparison ignores case for ASCII letters only, as the profile API
// does: "[Дом]" and "[дом]" are different sections.
bool SameName(std::string_view a, std::string_view b)
{
    if (a.size() != b.size())
        return false;
    for (size_t i = 0; i < a.size(); ++i) {
        char ca = a[i], cb = b[i];
        if (ca >= 'A' && ca <= 'Z') ca = static_cast<char>(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = static_cast<char>(cb - 'A' + 'a');
        if (ca != cb)
            return false;
    }
    return true;
}

// "[name]" → name, closed by the first ']'.
bool ParseHeader(std::string_view line, std::string_view& name)
{
    line = Trim(line);
    if (line.empty() || line.front() != '[')
        return false;
    const size_t close = line.find(']');
    if (close == std::string_view::npos)
        return false;
    name = Trim(line.substr(1, close - 1));
    return true;
}

// "key=value" → key. A line without '=' and a ';' comment are not keys.
std::string_view LineKey(std::string_view line)
{
    const size_t eq = line.find('=');
    if (eq == std::string_view::npos)
        return {};
    const std::string_view key = Trim(line.substr(0, eq));
    return !key.empty() && key.front() == ';' ? std::string_view() : key;
}

std::string_view LineValue(std::string_view line)
{
    const size_t eq = line.find('=');
    if (eq == std::string_view::npos)
        return {};
    std::string_view v = Trim(line.substr(eq + 1));
    if (v.size() >= 2 && (v.front() == '"' || v.front() == '\'') && v.back() == v.front())
        v = v.substr(1, v.size() - 2);
    return v;
}

// ---------------------------------------------------------------------------
// Parsed file cache
// ---------------------------------------------------------------------------

struct FileStamp {
    bool      exists = false;
    FILETIME  writeTime{};
    ULONGLONG size = 0;
};

struct IniDoc {
    bool                     loaded = false;
    FileStamp                stamp;
    std::vector<std::string> lines;   // UTF-8, without line breaks
};

std::mutex                     g_mutex;   // guards g_docs and every IniDoc
std::map<std::wstring, IniDoc> g_docs;    // keyed by full lower-case path

FileStamp ReadStamp(const std::wstring& path)
{
    FileStamp st;
    WIN32_FILE_ATTRIBUTE_DATA a{};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &a))
        return st;
    st.exists    = true;
    st.writeTime = a.ftLastWriteTime;
    st.size      = (static_cast<ULONGLONG>(a.nFileSizeHigh) << 32) | a.nFileSizeLow;
    return st;
}

bool SameStamp(const FileStamp& a, const FileStamp& b)
{
    if (a.exists != b.exists)
        return false;
    return !a.exists ||
           (a.size == b.size && CompareFileTime(&a.writeTime, &b.writeTime) == 0);
}

std::wstring DocKey(const std::wstring& path)
{
    const DWORD need = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
    std::wstring full = path;
    if (need > 0) {
        full.assign(need, L'\0');
        const DWORD len = GetFullPathNameW(path.c_str(), need, full.data(), nullptr);
        full.resize(len < need ? len : 0);
        if (full.empty())
            full = path;
    }
    CharLowerBuffW(full.data(), static_cast<DWORD>(full.size()));
    return full;
}

bool ReadAll(const std::wstring& path, std::string& out)
{
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return false;
    out.clear();
    char buf[65536];
    DWORD got = 0;
    bool ok = true;
    while ((ok = ReadFile(h, buf, sizeof(buf), &got, nullptr) != FALSE) && got > 0)
        out.append(buf, got);
    CloseHandle(h);
    return ok;
}

bool WriteAll(const std::wstring& path, const std::string& data)
{
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return false;
    DWORD written = 0;
    const bool ok = data.empty() ||
        (WriteFile(h, data.data(), static_cast<DWORD>(data.size()), &written, nullptr) &&
         written == data.size());
    CloseHandle(h);
    return ok;
}

void Load(const std::wstring& path, IniDoc& doc, const FileStamp& st)
{
    doc.lines.clear();
    doc.stamp  = st;
    doc.loaded = true;
    if (!st.exists)
        return;
    std::string raw;
    if (!ReadAll(path, raw)) {
        // Locked or vanished between the stamp and the read: try again on
        // the next call instead of caching an empty file.
        doc.loaded = false;
        return;
    }
    const std::string text = DecodeFile(raw);
    size_t pos = 0;
    while (pos < text.size()) {
        size_t nl = text.find('\n', pos);
        if (nl == std::string::npos)
            nl = text.size();
        std::string line = text.substr(pos, nl - pos);
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        doc.lines.push_back(std::move(line));
        pos = nl + 1;
    }
}

// The parsed file for `key`, re-read when the file on disk changed.
// Caller holds g_mutex.
IniDoc& GetDoc(const std::wstring& key)
{
    IniDoc& doc = g_docs[key];
    const FileStamp st = ReadStamp(key);
    if (!doc.loaded || !SameStamp(doc.stamp, st))
        Load(key, doc, st);
    return doc;
}

bool Save(const std::wstring& path, IniDoc& doc)
{
    std::string body;
    for (const auto& line : doc.lines) {
        body += line;
        body += "\r\n";
    }
    // Replace through a temporary copy so a reader never sees half a file.
    // When the target is held open without delete sharing, overwrite it in
    // place instead.
    const std::wstring tmp = path + L".tmp";
    bool ok = WriteAll(tmp, body) &&
              MoveFileExW(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
    if (!ok) {
        DeleteFileW(tmp.c_str());
        ok = WriteAll(path, body);
    }
    if (!ok) {
        doc.loaded = false;   // drop the unsaved change, re-read the disk
        return false;
    }
    doc.stamp = ReadStamp(path);
    return true;
}

// Serialises writers of one file across processes. Taken before g_mutex.
class PathLock {
public:
    explicit PathLock(const std::wstring& key)
    {
        unsigned hash = 2166136261u;
        for (wchar_t c : key)
            hash = (hash ^ static_cast<unsigned>(c)) * 16777619u;
        wchar_t name[48];
        swprintf_s(name, L"Local\\sftpplug-ini-%08x", hash);
        m_handle = CreateMutexW(nullptr, FALSE, name);
        if (m_handle) {
            // A writer that never lets go must not block us forever.
            const DWORD r = WaitForSingleObject(m_handle, 5000);
            m_owned = (r == WAIT_OBJECT_0 || r == WAIT_ABANDONED);
        }
    }
    ~PathLock()
    {
        if (m_owned)
            ReleaseMutex(m_handle);
        if (m_handle)
            CloseHandle(m_handle);
    }
    PathLock(const PathLock&)            = delete;
    PathLock& operator=(const PathLock&) = delete;

private:
    HANDLE m_handle = nullptr;
    bool   m_owned  = false;
};

// ---------------------------------------------------------------------------
// Document queries and edits (UTF-8)
// ---------------------------------------------------------------------------

struct Range {
    size_t header;   // index of the "[name]" line
    size_t begin;    // first line after the header
    size_t end;      // next header or end of file
};

// Requested names are trimmed like the ones in the file.
std::optional<Range> FindSection(const IniDoc& doc, std::string_view section)
{
    section = Trim(section);
    std::string_view name;
    for (size_t i = 0; i < doc.lines.size(); ++i) {
        if (!ParseHeader(doc.lines[i], name) || !SameName(name, section))
            continue;
        size_t end = i + 1;
        while (end < doc.lines.size() && !ParseHeader(doc.lines[end], name))
            ++end;
        return Range{ i, i + 1, end };
    }
    return std::nullopt;
}

std::optional<size_t> FindKey(const IniDoc& doc, const Range& r, std::string_view key)
{
    key = Trim(key);
    for (size_t i = r.begin; i < r.end; ++i) {
        const std::string_view k = LineKey(doc.lines[i]);
        if (!k.empty() && SameName(k, key))
            return i;
    }
    return std::nullopt;
}

std::vector<std::string> SectionNames(const IniDoc& doc)
{
    std::vector<std::string> out;
    std::string_view name;
    for (const auto& line : doc.lines)
        if (ParseHeader(line, name))
            out.emplace_back(name);
    return out;
}

std::vector<std::string> KeyNames(const IniDoc& doc, const Range& r)
{
    std::vector<std::string> out;
    for (size_t i = r.begin; i < r.end; ++i) {
        const std::string_view k = LineKey(doc.lines[i]);
        if (!k.empty())
            out.emplace_back(k);
    }
    return out;
}

bool SetValue(IniDoc& doc, std::string_view section, std::string_view key, std::string_view value)
{
    const auto r = FindSection(doc, section);
    if (!r) {
        doc.lines.push_back("[" + std::string(Trim(section)) + "]");
        doc.lines.push_back(std::string(Trim(key)) + "=" + std::string(value));
        return true;
    }
    if (const auto k = FindKey(doc, *r, key)) {
        // An existing key keeps its spelling from the file.
        std::string line = std::string(LineKey(doc.lines[*k])) + "=" + std::string(value);
        if (doc.lines[*k] == line)
            return false;
        doc.lines[*k] = std::move(line);
        return true;
    }
    std::string line = std::string(Trim(key)) + "=" + std::string(value);
    // New key goes after the last non-blank line of the section.
    size_t at = r->end;
    while (at > r->begin && Trim(doc.lines[at - 1]).empty())
        --at;
    doc.lines.insert(doc.lines.begin() + static_cast<std::ptrdiff_t>(at), std::move(line));
    return true;
}

bool DeleteKey(IniDoc& doc, std::string_view section, std::string_view key)
{
    const auto r = FindSection(doc, section);
    if (!r)
        return false;
    const auto k = FindKey(doc, *r, key);
    if (!k)
        return false;
    doc.lines.erase(doc.lines.begin() + static_cast<std::ptrdiff_t>(*k));
    return true;
}

bool DeleteSection(IniDoc& doc, std::string_view section)
{
    const auto r = FindSection(doc, section);
    if (!r)
        return false;
    // The header and its keys go; blank lines and comments stay where they were.
    doc.lines.erase(doc.lines.begin() + static_cast<std::ptrdiff_t>(r->header));
    const auto first = doc.lines.begin() + static_cast<std::ptrdiff_t>(r->begin - 1);
    const auto last  = doc.lines.begin() + static_cast<std::ptrdiff_t>(r->end - 1);
    doc.lines.erase(std::remove_if(first, last, [](const std::string& l) { return !LineKey(l).empty(); }),
                    last);
    return true;
}

// ---------------------------------------------------------------------------
// Copying results out with the profile API's truncation rules
// ---------------------------------------------------------------------------

template <typename Ch>
DWORD CopyValue(const std::basic_string<Ch>& v, Ch* out, DWORD outSize)
{
    const size_t n = std::min<size_t>(v.size(), outSize - 1);
    std::copy_n(v.data(), n, out);
    out[n] = 0;
    return static_cast<DWORD>(n);
}

// Double-null-terminated list. Too small a buffer gets a truncated list
// with two nulls at the end and the return value outSize - 2.
template <typename Ch>
DWORD CopyList(const std::vector<std::string>& items, Ch* out, DWORD outSize)
{
    std::basic_string<Ch> joined;
    std::basic_string<Ch> item;
    for (const auto& i : items) {
        FromUtf8(i, item);
        joined += item;
        joined.push_back(0);
    }
    if (outSize < 2) {
        out[0] = 0;
        return 0;
    }
    if (joined.size() + 1 <= outSize) {
        std::copy_n(joined.data(), joined.size(), out);
        out[joined.size()] = 0;
        if (joined.empty())
            out[1] = 0;
        return static_cast<DWORD>(joined.size());
    }
    std::copy_n(joined.data(), outSize - 2, out);
    out[outSize - 2] = 0;
    out[outSize - 1] = 0;
    return outSize - 2;
}

// ---------------------------------------------------------------------------
// Shared bodies of the ANSI and wide entry points
// ---------------------------------------------------------------------------

template <typename Ch>
DWORD GetStringT(const Ch* section, const Ch* key, const Ch* defaultValue,
                 Ch* out, DWORD outSize, const Ch* path)
{
    if (!out || outSize == 0)
        return 0;
    std::lock_guard<std::mutex> lock(g_mutex);
    const IniDoc& doc = GetDoc(DocKey(PathOf(path)));
    if (!section)
        return CopyList(SectionNames(doc), out, outSize);
    if (const auto r = FindSection(doc, ToUtf8(section))) {
        if (!key)
            return CopyList(KeyNames(doc, *r), out, outSize);
        if (const auto k = FindKey(doc, *r, ToUtf8(key))) {
            std::basic_string<Ch> v;
            FromUtf8(LineValue(doc.lines[*k]), v);
            return CopyValue(v, out, outSize);
        }
    }
    // The default loses trailing blanks, as with the profile API.
    std::basic_string<Ch> d = defaultValue ? defaultValue : std::basic_string<Ch>();
    while (!d.empty() && (d.back() == ' ' || d.back() == '\t'))
        d.pop_back();
    return CopyValue(d, out, outSize);
}

// Optional sign, then decimal or 0x hex digits; parsing stops at the first
// character that is not a digit.
INT ParseInt(std::string_view v)
{
    bool negative = false;
    if (!v.empty() && (v.front() == '-' || v.front() == '+')) {
        negative = v.front() == '-';
        v.remove_prefix(1);
    }
    unsigned base = 10;
    if (v.size() > 2 && v[0] == '0' && (v[1] == 'x' || v[1] == 'X')) {
        base = 16;
        v.remove_prefix(2);
    }
    unsigned result = 0;
    for (char c : v) {
        unsigned digit;
        if (c >= '0' && c <= '9')
            digit = static_cast<unsigned>(c - '0');
        else if (base == 16 && c >= 'a' && c <= 'f')
            digit = static_cast<unsigned>(c - 'a' + 10);
        else if (base == 16 && c >= 'A' && c <= 'F')
            digit = static_cast<unsigned>(c - 'A' + 10);
        else
            break;
        result = result * base + digit;
    }
    return negative ? -static_cast<INT>(result) : static_cast<INT>(result);
}

template <typename Ch>
UINT GetIntT(const Ch* section, const Ch* key, INT defaultValue, const Ch* path)
{
    if (!section || !key)
        return static_cast<UINT>(defaultValue);
    std::lock_guard<std::mutex> lock(g_mutex);
    const IniDoc& doc = GetDoc(DocKey(PathOf(path)));
    const auto r = FindSection(doc, ToUtf8(section));
    if (!r)
        return static_cast<UINT>(defaultValue);
    const auto k = FindKey(doc, *r, ToUtf8(key));
    if (!k)
        return static_cast<UINT>(defaultValue);
    const std::string_view v = LineValue(doc.lines[*k]);
    // An empty value counts as absent.
    if (v.empty())
        return static_cast<UINT>(defaultValue);
    return static_cast<UINT>(ParseInt(v));
}

template <typename Ch>
BOOL WriteStringT(const Ch* section, const Ch* key, const Ch* value, const Ch* path)
{
    if (!section || !path)
        return FALSE;
    const std::wstring docKey = DocKey(PathOf(path));
    PathLock fileLock(docKey);
    std::lock_guard<std::mutex> lock(g_mutex);
    // Re-read under the lock: another process may have written meanwhile.
    IniDoc& doc = GetDoc(docKey);
    const std::string sec = ToUtf8(section);
    bool changed;
    if (!key)
        changed = DeleteSection(doc, sec);
    else if (!value)
        changed = DeleteKey(doc, sec, ToUtf8(key));
    else
        changed = SetValue(doc, sec, ToUtf8(key), ToUtf8(value));
    if (!changed)
        return TRUE;
    return Save(docKey, doc) ? TRUE : FALSE;
}

}  // namespace

// ---------------------------------------------------------------------------
// Public entry points. Allocation failures end up as the profile API's
// failure results instead of leaving the plugin.
// ---------------------------------------------------------------------------

DWORD IniGetString(LPCSTR section, LPCSTR key, LPCSTR defaultValue,
                   LPSTR out, DWORD outSize, LPCSTR path)
{
    try {
        return GetStringT(section, key, defaultValue, out, outSize, path);
    } catch (...) {
        if (out && outSize)
            out[0] = 0;
        return 0;
    }
}

DWORD IniGetString(LPCWSTR section, LPCWSTR key, LPCWSTR defaultValue,
                   LPWSTR out, DWORD outSize, LPCWSTR path)
{
    try {
        return GetStringT(section, key, defaultValue, out, outSize, path);
    } catch (...) {
        if (out && outSize)
            out[0] = 0;
        return 0;
    }
}

UINT IniGetInt(LPCSTR section, LPCSTR key, INT defaultValue, LPCSTR path)
{
    try {
        return GetIntT(section, key, defaultValue, path);
    } catch (...) {
        return static_cast<UINT>(defaultValue);
    }
}

UINT IniGetInt(LPCWSTR section, LPCWSTR key, INT defaultValue, LPCWSTR path)
{
    try {
        return GetIntT(section, key, defaultValue, path);
    } catch (...) {
        return static_cast<UINT>(defaultValue);
    }
}

BOOL IniWriteString(LPCSTR section, LPCSTR key, LPCSTR value, LPCSTR path)
{
    try {
        return WriteStringT(section, key, value, path);
    } catch (...) {
        return FALSE;
    }
}

BOOL IniWriteString(LPCWSTR section, LPCWSTR key, LPCWSTR value, LPCWSTR path)
{
    try {
        return WriteStringT(section, key, value, path);
    } catch (...) {
        return FALSE;
    }
}

DWORD IniGetSectionNames(LPSTR out, DWORD outSize, LPCSTR path)
{
    return IniGetString(nullptr, nullptr, "", out, outSize, path);
}

DWORD IniGetSectionNames(LPWSTR out, DWORD outSize, LPCWSTR path)
{
    return IniGetString(nullptr, nullptr, L"", out, outSize, path);
}
