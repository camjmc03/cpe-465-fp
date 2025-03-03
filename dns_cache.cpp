#include "dns_cache.h"

DnsCache::DnsCache() {}

void DnsCache::addEntry(const std::string& domain, const std::vector<uint8_t>& response) {
    CacheEntry entry = {response, std::time(nullptr)};
    cache[domain] = entry;
}

bool DnsCache::getEntry(const std::string& domain, std::vector<uint8_t>& response) {
    auto it = cache.find(domain);
    if (it != cache.end()) {
        std::time_t now = std::time(nullptr);
        if (now - it->second.timestamp < cacheTTL) {
            response = it->second.response;
            return true;
        } else {
            cache.erase(it);
        }
    }
    return false;
}
