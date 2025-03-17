#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <time.h>
#include <yaml-cpp/yaml.h>
#include <net/if.h>
#include <ifaddrs.h>

// Define states for DNS requests
typedef enum {
    RECIEVED_QUERY,
    PARSE_QUERY,
    CACHE_CHECK,
    PENDING_RECURSION,
    PARSE_RECURSION,
    GENERATE_RESPONSE,
    SEND_RESPONSE,
    DONE
} RequestState;

// Structure to represent a DNS cache entry
struct DnsCacheEntry {
    uint8_t response[512];
    time_t expiry;
};

struct DnsRequest {
    uint8_t query[512];
    struct sockaddr_in clientAddr;
    socklen_t clientAddrLen;
    RequestState state;
    int queryLen;
};

// DNS cache
#define CACHE_SIZE 100
struct DnsCacheEntry dnsCache[CACHE_SIZE];

// Global variables for configuration
std::string server_ip;
std::string upstream_dns;
int dns_port;
int debug_level;

// Function to load configuration from config.yaml
void loadConfig() {
    try {
        YAML::Node config = YAML::LoadFile("config.yaml");
        server_ip = config["server_ip"].as<std::string>();
        upstream_dns = config["upstream_dns"].as<std::string>();
        dns_port = config["dns_port"].as<int>();
        debug_level = config["debug_level"].as<int>();

        if (debug_level >= 1) {
            printf("[DEBUG] Loaded configuration:\n");
            printf("  Server IP: %s\n", server_ip.c_str());
            printf("  Upstream DNS: %s\n", upstream_dns.c_str());
            printf("  DNS Port: %d\n", dns_port);
            printf("  Debug Level: %d\n", debug_level);
        }
    } catch (const YAML::Exception &e) {
        fprintf(stderr, "Error loading configuration: %s\n", e.what());
        exit(EXIT_FAILURE);
    }
}

// Function to parse DNS query and extract the requested domain name
void parseDnsQuery(uint8_t *query, char *domainName) {
    int i = 12;
    int pos = 0;
    while (query[i] != 0) {
        int len = query[i];
        memcpy(domainName + pos, query + i + 1, len);
        pos += len;
        domainName[pos++] = '.';
        i += len + 1;
    }
    domainName[pos - 1] = '\0';

    if (debug_level >= 3) {
        printf("[DEBUG] Parsed domain name: %s\n", domainName);
    }
}

// Function to check if the DNS response is in the cache
int isResponseCached(const char *domainName, uint8_t *response, uint16_t transactionID) {
    if (debug_level >= 2) {
        printf("[DEBUG] Checking cache for domain: %s\n", domainName);
    }
    for (int i = 0; i < CACHE_SIZE; i++) {
        if (dnsCache[i].expiry > time(NULL)) {
            char cachedDomain[256];
            parseDnsQuery(dnsCache[i].response, cachedDomain); // Extract domain from cached response
            if (strcmp(cachedDomain, domainName) == 0) {
                if (debug_level >= 2) {
                    printf("[DEBUG] Cache hit for domain: %s\n", domainName);
                }
                memcpy(response, dnsCache[i].response, 512);

                // Update the transaction ID in the cached response
                response[0] = (transactionID >> 8) & 0xFF; // High byte
                response[1] = transactionID & 0xFF;        // Low byte

                return 1;
            }
        }
    }
    if (debug_level >= 2) {
        printf("[DEBUG] Cache miss for domain: %s\n", domainName);
    }
    return 0;
}

// Function to cache the DNS response
void cacheDnsResponse(const char *domainName, uint8_t *response) {
    int ttl = 60; // Default TTL of 60 seconds
    for (int i = 0; i < CACHE_SIZE; i++) {
        if (dnsCache[i].expiry < time(NULL)) {
            memcpy(dnsCache[i].response, response, 512);
            dnsCache[i].expiry = time(NULL) + ttl;
            if (debug_level >= 2) {
                printf("[DEBUG] Cached response for domain: %s\n", domainName);
            }
            break;
        }
    }
}

int main() {
    loadConfig();

    int sockfd, maxfd;
    struct sockaddr_in serverAddr, clientAddr, upstreamAddr;
    fd_set readfds;
    struct DnsRequest requests[FD_SETSIZE];
    int requestCount = 0;

    // Initialize UDP socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Attempt to bind socket to the IP address specified in config.yaml
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr(server_ip.c_str());
    serverAddr.sin_port = htons(dns_port);
    // if server ip or port not given, skip binding to specific IP or port
    if ( server_ip == "default" ) {
        printf("[INFO] \"default\" given for IP, binding to first available IP\n");
        serverAddr.sin_addr.s_addr = INADDR_ANY;
    }
    if (bind(sockfd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }
    if (debug_level >= 1) {
        // print the server IP and port
        printf("[DEBUG] Listening on %s:%d\n", server_ip.c_str(), dns_port);
    }

    // Set up upstream DNS server address (e.g., 8.8.8.8)
    memset(&upstreamAddr, 0, sizeof(upstreamAddr));
    upstreamAddr.sin_family = AF_INET;
    upstreamAddr.sin_port = htons(53);
    inet_pton(AF_INET, upstream_dns.c_str(), &upstreamAddr.sin_addr);

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);
        maxfd = sockfd;

        // Use select to wait for incoming requests
        if (select(maxfd + 1, &readfds, NULL, NULL, NULL) < 0) {
            perror("select");
            exit(EXIT_FAILURE);
        }

        if (FD_ISSET(sockfd, &readfds)) {
            struct DnsRequest request;
            request.clientAddrLen = sizeof(request.clientAddr);
            request.queryLen = recvfrom(sockfd, request.query, sizeof(request.query), 0,
                                        (struct sockaddr *)&request.clientAddr, &request.clientAddrLen);
            if (request.queryLen < 0) {
                perror("recvfrom");
                continue;
            }

            if (debug_level >= 1) {
                printf("[DEBUG] Received DNS query from %s:%d\n",
                       inet_ntoa(request.clientAddr.sin_addr), ntohs(request.clientAddr.sin_port));
            }

            char domainName[256];
            parseDnsQuery(request.query, domainName);

            uint8_t response[512];
            if (isResponseCached(domainName, response, ntohs(*(uint16_t *)request.query))) {
                // Send cached response to client
                sendto(sockfd, response, sizeof(response), 0,
                       (struct sockaddr *)&request.clientAddr, request.clientAddrLen);

                if (debug_level >= 1) {
                    printf("[DEBUG] Sent cached response to %s:%d\n",
                           inet_ntoa(request.clientAddr.sin_addr), ntohs(request.clientAddr.sin_port));
                }
            } else {
                // Forward query to upstream DNS server
                sendto(sockfd, request.query, request.queryLen, 0,
                       (struct sockaddr *)&upstreamAddr, sizeof(upstreamAddr));

                if (debug_level >= 1) {
                    printf("[DEBUG] Forwarded query for domain %s to upstream DNS server\n", domainName);
                }

                // Receive response from upstream DNS server
                int responseLen = recvfrom(sockfd, response, sizeof(response), 0, NULL, NULL);
                if (responseLen < 0) {
                    perror("recvfrom");
                    continue;
                }

                if (debug_level >= 1) {
                    printf("[DEBUG] Received response from upstream DNS server for domain %s\n", domainName);
                }

                // Cache the response
                cacheDnsResponse(domainName, response);

                // Send response to client
                sendto(sockfd, response, responseLen, 0,
                       (struct sockaddr *)&request.clientAddr, request.clientAddrLen);

                if (debug_level >= 1) {
                    printf("[DEBUG] Sent response to %s:%d\n",
                           inet_ntoa(request.clientAddr.sin_addr), ntohs(request.clientAddr.sin_port));
                }

                if (debug_level >= 3) {
                    printf("[DEBUG] Response hexdump:\n");
                    for (int i = 0; i < responseLen; i++) {
                        printf("%02x ", response[i]);
                        if ((i + 1) % 16 == 0) {
                            printf("\n");
                        }
                    }
                    printf("\n");
                }
            }
        }
    }

    close(sockfd);
    return 0;
}