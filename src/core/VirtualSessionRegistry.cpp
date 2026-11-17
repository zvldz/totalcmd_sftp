#include "VirtualSessionRegistry.h"
#include "ImportIoUtil.h"

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

// 64-bit FNV-1a: two cache sections sharing an alias would share a
// connection, so the alias is kept far from any collision.
unsigned long long Fnv1a64(std::string_view s) noexcept
{
    unsigned long long h = 14695981039346656037ull;
    for (const unsigned char c : s)
        h = (h ^ c) * 1099511628211ull;
    return h;
}

}  // namespace

std::string MakeVirtualSessionAlias(const std::string& sourceId,
                                    const std::string& cacheSection)
{
    // Hash the full cache-section name so identical (sourceId, displayName)
    // input always produces the same alias — reconnect after disconnect
    // routes to the same slot, and mismatched sourceId cannot collide with
    // a session from a different adapter.
    char hex[24];
    std::snprintf(hex, sizeof(hex), "%016llx", Fnv1a64(cacheSection));

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
