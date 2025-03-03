#ifndef DNS_CACHE_H
#define DNS_CACHE_H

#include <unordered_map>
#include <string>
#include <vector>
#include <ctime>

class DnsCache {
public:
    DnsCache();
    void addEntry(const std::string& domain, const std::vector<uint8_t>& response);
    bool getEntry(const std::string& domain, std::vector<uint8_t>& response);

private:
    struct CacheEntry {
        std::vector<uint8_t> response;
        std::time_t timestamp;
    };

    std::unordered_map<std::string, CacheEntry> cache;
    std::time_t cacheTTL = 300; // Time-to-live for cache entries in seconds
};

#endif // DNS_CACHE_H