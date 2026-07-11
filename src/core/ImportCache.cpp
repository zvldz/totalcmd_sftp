#include "ImportCache.h"
#include "PluginEntryPointsInternal.h"
#include "SftpClient.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <algorithm>
#include <array>
#include <vector>

namespace sftp {

namespace {

constexpr const char* kSectionPrefix    = "__import.";
constexpr size_t      kSectionPrefixLen = 9;

// Resolve on-disk cache path from the plugin's inifilename[] global.
// Cache file lives in the same directory as sftpplug.ini.
std::string ResolveCachePath()
{
    if (inifilename[0] == '\0')
        return {};
    std::string p(inifilename);
    const size_t sep = p.find_last_of("\\/");
    std::string dir = (sep == std::string::npos) ? std::string(".") : p.substr(0, sep);
    return dir + "\\sftpplug-imports-cache.ini";
}

// FNV-1a 32-bit hash. Stable across runs and platforms; we only need it as
// a short opaque identifier for the channel string inside on-disk section
// names, so any deterministic hash would do. Chosen for its brevity.
uint32_t Fnv1aHash(std::string_view s) noexcept
{
    uint32_t h = 0x811c9dc5u;
    for (unsigned char c : s) {
        h ^= c;
        h *= 0x01000193u;
    }
    return h;
}

std::string ChannelTag(std::string_view channel) noexcept
{
    char buf[16];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%08x", Fnv1aHash(channel));
    return buf;
}

// Split "__import.<sourceId>.<channelTag>.<displayName>" back into
// components. Both sourceId and channelTag are `.`-free — sourceId is a
// fixed adapter identifier (e.g. "securecrt") and channelTag is 8 hex
// chars — so the first two `.` separators are unambiguous. displayName
// can contain `.` freely and is whatever follows.
bool ParseSectionName(const std::string& section,
                      std::string& outSourceId,
                      std::string& outChannelTag,
                      std::string& outDisplayName)
{
    if (section.compare(0, kSectionPrefixLen, kSectionPrefix) != 0)
        return false;
    const size_t dot1 = section.find('.', kSectionPrefixLen);
    if (dot1 == std::string::npos) return false;
    const size_t dot2 = section.find('.', dot1 + 1);
    if (dot2 == std::string::npos) return false;
    outSourceId    = section.substr(kSectionPrefixLen, dot1 - kSectionPrefixLen);
    outChannelTag  = section.substr(dot1 + 1, dot2 - dot1 - 1);
    outDisplayName = section.substr(dot2 + 1);
    return true;
}

std::string ReadSourceTag(const std::string& section, const std::string& iniPath)
{
    std::array<char, 512> buf{};
    GetPrivateProfileStringA(section.c_str(), "_source", "",
                              buf.data(), static_cast<DWORD>(buf.size()),
                              iniPath.c_str());
    return buf.data();
}

// Persist one adapter-produced session as an INI section.
//
// Contract: the adapter populates any subset of tConnectSettings it can
// recover; the writer persists exactly the fields that carry a non-sentinel
// value. Sentinel = "adapter did not touch this key":
//   * std::string  — empty
//   * bool         — false
//   * utf8names / unixlinebreaks — -1 (the tri-state "auto")
// A field left at its sentinel means "unknown, don't cache" (not "off"),
// so downstream materialise leaves the corresponding session key absent
// and native code paths fall back to their own defaults.
//
// EXTEND CAUTION: when a future adapter starts populating a new field
// (proxy references, jump-host references, per-session codepage, …),
// add the corresponding `if (sentinel) ... else Write(...)` block below
// so the field actually reaches the cache. Silent drops here surface as
// "everything looked right in the enumerate, but the materialised session
// has no proxy" bugs three phases downstream. See TODO — Phase 1 audit
// remaining polish for the field-mask alternative.
void WriteSessionSection(const std::string& section,
                         const std::string& iniPath,
                         const tConnectSettings* s,
                         const std::string& sourceOrigin)
{
    // Clear any previous section content, then rewrite.
    WritePrivateProfileStringA(section.c_str(), nullptr, nullptr, iniPath.c_str());
    if (!s) return;

    // Channel provenance tag. Always present.
    WritePrivateProfileStringA(section.c_str(), "_source",
                                sourceOrigin.c_str(), iniPath.c_str());

    if (!s->server.empty())
        WritePrivateProfileStringA(section.c_str(), "server",
                                    s->server.c_str(), iniPath.c_str());
    if (!s->user.empty())
        WritePrivateProfileStringA(section.c_str(), "user",
                                    s->user.c_str(), iniPath.c_str());
    if (!s->pubkeyfile.empty())
        WritePrivateProfileStringA(section.c_str(), "pubkeyfile",
                                    s->pubkeyfile.c_str(), iniPath.c_str());
    if (!s->privkeyfile.empty())
        WritePrivateProfileStringA(section.c_str(), "privkeyfile",
                                    s->privkeyfile.c_str(), iniPath.c_str());
    if (s->useagent)
        WritePrivateProfileStringA(section.c_str(), "useagent",
                                    "1", iniPath.c_str());

    // Password lands in the cache when the adapter successfully recovered
    // it (WinSCP weak-XOR, KiTTY external decrypt helper). SecureCRT leaves
    // it empty by design and it is not cached. The stored value uses the
    // same DPAPI-encrypted representation the native session store does —
    // the cache file lives next to sftpplug.ini and is not more exposed.
    if (!s->password.empty())
        WritePrivateProfileStringA(section.c_str(), "password",
                                    s->password.c_str(), iniPath.c_str());

    // utf8names / unixlinebreaks are tri-state (-1 = auto, 0 = no, 1 = yes).
    // -1 means "not populated by the adapter" — skip.
    if (s->utf8names == 0 || s->utf8names == 1)
        WritePrivateProfileStringA(section.c_str(), "utf8",
                                    s->utf8names == 1 ? "1" : "0",
                                    iniPath.c_str());
    if (s->unixlinebreaks == 0 || s->unixlinebreaks == 1)
        WritePrivateProfileStringA(section.c_str(), "unixlinebreaks",
                                    s->unixlinebreaks == 1 ? "1" : "0",
                                    iniPath.c_str());
}

}  // namespace

ImportCache& GetImportCache()
{
    static ImportCache instance;
    // Load the on-disk cache exactly once, right after the singleton is
    // constructed. Uses a local-static-with-lambda so C++11's thread-safe
    // static init guarantees Load() runs at most once even if the first
    // access races between panel threads. Without this call the in-memory
    // map stays empty across TC restarts and every [Imports]\<Source>\
    // listing shows only the pseudo entries until the user hits [Refresh],
    // even though the cache file on disk is intact.
    [[maybe_unused]] static const bool _loaded = (instance.Load(), true);
    return instance;
}

ImportCache::ImportCache()
    : m_cachePath(ResolveCachePath())
{
}

std::string ImportCache::SectionName(const std::string& sourceId,
                                      const std::string& channel,
                                      const std::string& displayName) noexcept
{
    return std::string(kSectionPrefix) + sourceId + "." +
           ChannelTag(channel) + "." + displayName;
}

std::string ImportCache::SectionNameForConnect(const std::string& sourceId,
                                                const std::string& displayName) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& r : m_sessions) {
        if (r.sourceId == sourceId && r.displayName == displayName)
            return SectionName(sourceId, r.sourceOrigin, displayName);
    }
    return {};
}

void ImportCache::Load()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_loaded) return;
    m_loaded = true;

    // Cache path may resolve empty if Load() is called before FsSetDefaultParams
    // has populated inifilename[]. In that case we silently skip; the next
    // access is expected to happen after plugin init.
    if (m_cachePath.empty())
        return;

    // Enumerate every section in the cache INI, filter by our prefix,
    // reconstruct in-memory refs. Read _source tag inline to remember
    // channel provenance across TC restarts.
    std::vector<char> buf(65536, '\0');
    const DWORD len = GetPrivateProfileSectionNamesA(buf.data(),
                                                      static_cast<DWORD>(buf.size()),
                                                      m_cachePath.c_str());
    if (len == 0) return;

    const char* p = buf.data();
    while (*p) {
        const std::string section(p);
        p += section.size() + 1;

        std::string sourceId, channelTag, displayName;
        if (!ParseSectionName(section, sourceId, channelTag, displayName))
            continue;

        CachedSessionRef ref;
        ref.sourceId     = std::move(sourceId);
        ref.displayName  = std::move(displayName);
        // sourceOrigin is the literal channel string (e.g. "standard" or a
        // Windows path); it's stored inside the section as `_source`. We
        // cannot recover it from the hashed channelTag alone.
        ref.sourceOrigin = ReadSourceTag(section, m_cachePath);
        m_sessions.push_back(std::move(ref));
    }
}

std::vector<CachedSessionRef>
ImportCache::ListSource(const std::string& sourceId) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<CachedSessionRef> out;
    for (const auto& s : m_sessions) {
        if (s.sourceId == sourceId)
            out.push_back(s);
    }
    return out;
}

// Sections are per (sourceId, channel, displayName) — each channel owns
// its own set of disk sections and independent memory refs. Prune and
// Replace touch only the requested channel's rows; other channels are
// oblivious. Display-time de-duplication in BuildImportsSourceListing
// hides the fact that multiple channels can share a displayName.
void ImportCache::EraseChannelLocked(const std::string& sourceId,
                                      const std::string& channel)
{
    auto is_target = [&](const CachedSessionRef& r) {
        return r.sourceId == sourceId && r.sourceOrigin == channel;
    };
    for (const auto& r : m_sessions) {
        if (is_target(r)) {
            const std::string section = SectionName(r.sourceId, channel, r.displayName);
            WritePrivateProfileStringA(section.c_str(), nullptr, nullptr,
                                        m_cachePath.c_str());
        }
    }
    m_sessions.erase(
        std::remove_if(m_sessions.begin(), m_sessions.end(), is_target),
        m_sessions.end());
}

void ImportCache::ReplaceChannel(const std::string& sourceId,
                                  const std::string& channel,
                                  const std::vector<CacheWriteEntry>& newSessions)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_cachePath.empty()) return;

    EraseChannelLocked(sourceId, channel);

    // Add the new scan results as fresh sections + memory refs. All rows
    // added here share the same `channel` provenance, so a later
    // PruneChannel or [Manage custom locations] removal (also keyed on
    // channel) matches every row this call inserted.
    for (const auto& w : newSessions) {
        const std::string section =
            SectionName(sourceId, channel, w.displayName);
        WriteSessionSection(section, m_cachePath, w.settings, channel);
        CachedSessionRef ref;
        ref.sourceId     = sourceId;
        ref.displayName  = w.displayName;
        ref.sourceOrigin = channel;
        m_sessions.push_back(std::move(ref));
    }
}

void ImportCache::PruneChannel(const std::string& sourceId,
                                const std::string& channel)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_cachePath.empty()) return;
    EraseChannelLocked(sourceId, channel);
}

}  // namespace sftp
