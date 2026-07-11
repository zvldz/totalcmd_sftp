#pragma once

#include <string>
#include <vector>

struct tConnectSettings;
typedef tConnectSettings* pConnectSettings;

namespace sftp {

// One session reported by an adapter.
// displayName uses '/' as folder separator (round-trips through our path
// normalisation). sourceOrigin identifies the channel the entry came from —
// the literal strings "registry", "appdata", or the custom-path itself.
// Used as the _source tag in the on-disk cache to support per-channel prune
// rules.
struct ExternalSessionEntry {
    std::string displayName;
    std::string sourceOrigin;
};

// Adapter's verdict for one channel probe. Drives cache prune behaviour:
// Unreachable → keep existing cached entries; OkEmpty → prune this channel;
// OkWithSessions → replace this channel's cached entries with `sessions`.
enum class EnumerationStatus {
    Unreachable,
    OkEmpty,
    OkWithSessions
};

struct EnumerationResult {
    EnumerationStatus                 status = EnumerationStatus::Unreachable;
    std::vector<ExternalSessionEntry> sessions;
};

// Chrome the plugin should use for the [Add custom location…] pseudo entry.
// Every adapter declares one:
//   None    — the entry is hidden entirely. Use for adapters with no
//             portable/custom-path concept (e.g. a strict registry-only
//             source whose sessions all live in one well-known place).
//   Folder  — a folder is picked; passed to EnumerateCustomPath() as-is.
//             Fits portable-install trees (SecureCRT, KiTTY, WinSCP
//             portable directory, …).
//   File    — a single file is picked; passed to EnumerateCustomPath() as
//             the full file path. Fits export-file sources (putty.reg,
//             sitemanager.xml). The adapter also supplies a Win32 filter
//             string via CustomPathFileFilter().
enum class CustomPathPickerKind { None, Folder, File };

// One adapter per source program (SecureCRT, PuTTY, ...).
// Registered in ImportSourceRegistry at plugin startup.
class IExternalSessionSource {
public:
    virtual ~IExternalSessionSource() = default;

    // Lowercase ASCII identifier. Used as prefix in cache section names
    // ("__import.<sourceId>.<name>") and ini keys ("<sourceId>.custom_paths").
    virtual const char* SourceId() const noexcept = 0;

    // User-facing folder name in the plugin root, e.g. "[SecureCRT]".
    virtual const char* FolderName() const noexcept = 0;

    // Cheap probe. True if the source is available at its standard location
    // (registry key present, canonical %APPDATA% marker file exists, ...).
    virtual bool DetectStandard() const noexcept = 0;

    // Full walk of the standard location. Populates result.sessions on
    // OkWithSessions. Called on [Refresh]; also on plugin startup as part of
    // detection-driven visibility.
    virtual EnumerationResult EnumerateStandard() = 0;

    // Full walk of one user-supplied path. Called on [Refresh] per configured
    // path, and immediately after [Add custom location…].
    virtual EnumerationResult EnumerateCustomPath(const std::string& path) = 0;

    // Fills tConnectSettings for a specific session previously reported by
    // one of the Enumerate* calls. Password fields intentionally left
    // untouched — the plugin surfaces the standard interactive prompt on
    // first connect. Returns true on success.
    virtual bool LoadSettings(const ExternalSessionEntry& entry,
                              pConnectSettings out) = 0;

    // See CustomPathPickerKind. Consulted by BuildImportsSourceListing to
    // decide whether to surface [Add custom location…] at all, and by
    // FsExecuteFileW to pick between the folder- and file-picker.
    virtual CustomPathPickerKind CustomPathPicker() const noexcept = 0;

    // Only meaningful when CustomPathPicker() == File. NUL-separated Win32
    // filter string ("PuTTY export\0*.reg\0All files\0*.*\0"). Adapters
    // returning Folder or None can leave the default nullptr — callers never
    // dereference it in those cases.
    virtual const char* CustomPathFileFilter() const noexcept { return nullptr; }
};

}  // namespace sftp
