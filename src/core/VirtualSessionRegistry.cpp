#include "VirtualSessionRegistry.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdio>
#include <cstring>
#include <mutex>
#include <string_view>
#include <unordered_map>

namespace sftp {

namespace {

constexpr const char* kAliasPrefix    = "__vimp_";
constexpr size_t      kAliasPrefixLen = 7;

// FNV-1a 32-bit — the same variant used inside ImportCache for channel-tag
// hashing; kept local here rather than shared to avoid an include dependency
// on ImportCache internals from this stand-alone registry.
uint32_t Fnv1a(std::string_view s) noexcept
{
    uint32_t h = 0x811c9dc5u;
    for (unsigned char c : s) {
        h ^= c;
        h *= 0x01000193u;
    }
    return h;
}

std::mutex&                                    Mutex()
{
    static std::mutex m;
    return m;
}

std::unordered_map<std::string, VirtualSessionInfo>& Map()
{
    static std::unordered_map<std::string, VirtualSessionInfo> m;
    return m;
}

}  // namespace

std::string MakeVirtualSessionAlias(const std::string& sourceId,
                                    const std::string& cacheSection)
{
    // Hash the full cache-section name so identical (sourceId, displayName)
    // input always produces the same alias — reconnect after disconnect
    // routes to the same slot, and mismatched sourceId cannot collide with
    // a session from a different adapter.
    char hex[16];
    std::snprintf(hex, sizeof(hex), "%08x", Fnv1a(cacheSection));

    std::string out(kAliasPrefix);
    out.append(sourceId);
    out.push_back('_');
    out.append(hex);
    return out;
}

bool IsVirtualSessionAlias(const char* name) noexcept
{
    if (!name) return false;
    return std::strncmp(name, kAliasPrefix, kAliasPrefixLen) == 0;
}

void RegisterVirtualSession(const std::string& alias, VirtualSessionInfo info)
{
    std::lock_guard<std::mutex> lock(Mutex());
    Map()[alias] = std::move(info);
}

std::optional<VirtualSessionInfo> LookupVirtualSession(const std::string& alias)
{
    std::lock_guard<std::mutex> lock(Mutex());
    auto it = Map().find(alias);
    if (it == Map().end())
        return std::nullopt;
    return it->second;
}

void UnregisterVirtualSession(const std::string& alias)
{
    std::lock_guard<std::mutex> lock(Mutex());
    Map().erase(alias);
}

}  // namespace sftp
