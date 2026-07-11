#include "ImportIoUtil.h"

#include <commdlg.h>
#include <shlobj.h>

#include <array>
#include <cstring>
#include <vector>

namespace sftp {

namespace {

int CALLBACK BrowseFolderInitCallback(HWND hwnd, UINT msg, LPARAM /*lParam*/, LPARAM lpData)
{
    if (msg == BFFM_INITIALIZED && lpData)
        SendMessageW(hwnd, BFFM_SETSELECTIONW, TRUE, lpData);
    return 0;
}


// Case-insensitive extension match. `name` is the leaf (e.g. "Session.INI"),
// `ext` is the required extension without a leading dot (e.g. "ini"). Empty
// `ext` matches every regular file.
bool ExtensionMatches(const std::wstring& name, const std::wstring& ext) noexcept
{
    if (ext.empty()) return true;
    if (name.size() <= ext.size() + 1) return false;
    if (name[name.size() - ext.size() - 1] != L'.') return false;
    return _wcsicmp(name.c_str() + name.size() - ext.size(), ext.c_str()) == 0;
}

// Build the relative DisplayName segment for a file. `parentRel` is the
// slash-joined relative path of the file's parent directory (empty at
// `root`); `leaf` is the file name with its extension already validated by
// ExtensionMatches. Trailing `.ext` is stripped from the leaf.
std::string BuildRelPath(const std::string& parentRel,
                          const std::wstring& leaf,
                          const std::wstring& ext)
{
    std::wstring baseW = leaf;
    if (!ext.empty() && baseW.size() > ext.size() + 1)
        baseW.resize(baseW.size() - ext.size() - 1);  // drop ".ext"

    // Wide → UTF-8 for the DisplayName segment.
    const int need = WideCharToMultiByte(CP_UTF8, 0,
        baseW.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string leafU8;
    if (need > 1) {
        leafU8.resize(static_cast<size_t>(need - 1));
        WideCharToMultiByte(CP_UTF8, 0, baseW.c_str(), -1,
            leafU8.data(), need, nullptr, nullptr);
    }
    if (parentRel.empty()) return leafU8;
    return parentRel + "/" + leafU8;
}

// Depth-first recursion body. Stops the whole walk (returns false all the
// way up) as soon as the visitor returns false.
bool WalkImpl(const std::wstring& dir,
              const std::string&  parentRel,
              const std::wstring& ext,
              WalkFileCallback&   onFile)
{
    const std::wstring pattern = dir + L"\\*";
    WIN32_FIND_DATAW fd{};
    HANDLE hFind = FindFirstFileW(pattern.c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE) return true;

    std::vector<std::wstring> subdirs;

    bool keepGoing = true;
    do {
        const wchar_t* name = fd.cFileName;
        if (name[0] == L'.' &&
            (name[1] == L'\0' || (name[1] == L'.' && name[2] == L'\0')))
            continue;

        const std::wstring leaf(name);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            subdirs.push_back(dir + L"\\" + leaf);
            continue;
        }

        if (!ExtensionMatches(leaf, ext))
            continue;

        const std::wstring fullPath = dir + L"\\" + leaf;
        const std::string  relPath  = BuildRelPath(parentRel, leaf, ext);
        if (!onFile(fullPath, relPath)) {
            keepGoing = false;
            break;
        }
    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);

    if (!keepGoing) return false;

    for (const auto& sub : subdirs) {
        const size_t slash = sub.find_last_of(L'\\');
        const std::wstring leafW = (slash == std::wstring::npos)
            ? sub
            : sub.substr(slash + 1);
        const std::string childRel =
            BuildRelPath(parentRel, leafW, L"");  // no extension strip for dirs
        if (!WalkImpl(sub, childRel, ext, onFile))
            return false;
    }
    return true;
}

}  // namespace

bool IniSectionExists(const std::string& section, LPCSTR iniPath) noexcept
{
    if (section.empty() || !iniPath || !iniPath[0]) return false;
    std::array<char, 16> buf{};
    if (GetPrivateProfileStringA(section.c_str(), "server", nullptr,
            buf.data(), static_cast<DWORD>(buf.size()), iniPath) > 0)
        return true;
    return GetPrivateProfileStringA(section.c_str(), "user", nullptr,
            buf.data(), static_cast<DWORD>(buf.size()), iniPath) > 0;
}

void WalkDirectoryFiles(const std::wstring& root,
                        const std::wstring& ext,
                        WalkFileCallback     onFile)
{
    if (root.empty() || !onFile) return;
    WalkImpl(root, {}, ext, onFile);
}

namespace {

// Convert an ANSI, NUL-separated Win32 filter ("A\0*.a\0B\0*.b\0") into a
// wide, NUL-separated buffer with the required trailing double-NUL. Returns
// empty vector on empty input.
std::vector<wchar_t> WidenNulSeparatedFilter(const char* filter)
{
    if (!filter || !filter[0]) return {};

    // Total ANSI length up to and including the terminating double-NUL.
    size_t ansiLen = 0;
    while (true) {
        const size_t segLen = std::strlen(filter + ansiLen);
        ansiLen += segLen + 1;  // include the segment's NUL
        if (segLen == 0) break;  // empty segment marks the end
    }

    const int wchars = MultiByteToWideChar(CP_ACP, 0, filter,
        static_cast<int>(ansiLen), nullptr, 0);
    if (wchars <= 0) return {};
    std::vector<wchar_t> out(static_cast<size_t>(wchars), L'\0');
    MultiByteToWideChar(CP_ACP, 0, filter, static_cast<int>(ansiLen),
        out.data(), wchars);
    return out;
}

}  // namespace

bool BrowseForFile(HWND               owner,
                   const char*        title,
                   const char*        filter,
                   const char*        initialPath,
                   std::string&       outPath)
{
    wchar_t wTitle[256] = {};
    if (title && title[0])
        MultiByteToWideChar(CP_ACP, 0, title, -1, wTitle, 256);

    // GetOpenFileName expects a mutable buffer that both seeds the initial
    // selection and receives the picked path. Pre-fill with `initialPath`
    // when it's a full file path; a bare directory goes into lpstrInitialDir.
    wchar_t wFile[MAX_PATH] = {};
    wchar_t wInitDir[MAX_PATH] = {};
    if (initialPath && initialPath[0]) {
        const DWORD attrs = GetFileAttributesA(initialPath);
        if (attrs != INVALID_FILE_ATTRIBUTES &&
            (attrs & FILE_ATTRIBUTE_DIRECTORY))
        {
            MultiByteToWideChar(CP_ACP, 0, initialPath, -1,
                wInitDir, MAX_PATH);
        } else {
            MultiByteToWideChar(CP_ACP, 0, initialPath, -1,
                wFile, MAX_PATH);
        }
    }

    const std::vector<wchar_t> wFilter = WidenNulSeparatedFilter(filter);

    OPENFILENAMEW ofn = {};
    ofn.lStructSize  = sizeof(ofn);
    ofn.hwndOwner    = owner;
    ofn.lpstrTitle   = wTitle[0] ? wTitle : nullptr;
    ofn.lpstrFile    = wFile;
    ofn.nMaxFile     = MAX_PATH;
    ofn.lpstrFilter  = wFilter.empty() ? nullptr : wFilter.data();
    ofn.lpstrInitialDir = wInitDir[0] ? wInitDir : nullptr;
    ofn.Flags        = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST |
                       OFN_HIDEREADONLY | OFN_NOCHANGEDIR;

    if (!GetOpenFileNameW(&ofn)) return false;

    char narrow[MAX_PATH * 4] = {};
    WideCharToMultiByte(CP_ACP, 0, wFile, -1,
                         narrow, sizeof(narrow), nullptr, nullptr);
    outPath.assign(narrow);
    return !outPath.empty();
}

bool BrowseForFolder(HWND               owner,
                     const char*        title,
                     const char*        initialPath,
                     std::string&       outPath)
{
    wchar_t wTitle[256] = {};
    if (title && title[0])
        MultiByteToWideChar(CP_ACP, 0, title, -1, wTitle, 256);

    wchar_t wInitial[MAX_PATH] = {};
    if (initialPath && initialPath[0])
        MultiByteToWideChar(CP_ACP, 0, initialPath, -1, wInitial, MAX_PATH);

    BROWSEINFOW bi = {};
    bi.hwndOwner = owner;
    bi.lpszTitle = wTitle[0] ? wTitle : nullptr;
    bi.ulFlags   = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE | BIF_USENEWUI;
    if (wInitial[0]) {
        bi.lpfn   = BrowseFolderInitCallback;
        bi.lParam = reinterpret_cast<LPARAM>(wInitial);
    }

    LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
    if (!pidl) return false;

    wchar_t wpath[MAX_PATH] = {};
    const bool got = SHGetPathFromIDListW(pidl, wpath) != 0;
    CoTaskMemFree(pidl);
    if (!got) return false;

    char narrow[MAX_PATH * 4] = {};
    WideCharToMultiByte(CP_ACP, 0, wpath, -1,
                         narrow, sizeof(narrow), nullptr, nullptr);
    outPath.assign(narrow);
    return !outPath.empty();
}

}  // namespace sftp
