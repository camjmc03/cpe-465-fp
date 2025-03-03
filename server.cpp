#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fstream>
#include <yaml-cpp/yaml.h>
#include <csignal>
#include <cerrno>
#include "dns_cache.h"

#define BUFFER_SIZE 512

std::string server_ip;
std::string upstream_dns;
std::string interface;
int dns_port;
int debug_level;
DnsCache cache;

void loadConfig() {
    YAML::Node config = YAML::LoadFile("config.yaml");
    server_ip = config["server_ip"].as<std::string>();
    upstream_dns = config["upstream_dns"].as<std::string>();
    interface = config["interface"].as<std::string>();
    dns_port = config["dns_port"].as<int>();
    debug_level = config["debug_level"].as<int>();
}

void process_packet(u_char *user, const struct pcap_pkthdr *packet_header, const u_char *packet);
void send_dns_response(int sockfd, struct sockaddr_in *client_addr, socklen_t addr_len, const u_char *response, int response_len, uint16_t transaction_id);

void process_packet(u_char *user, const struct pcap_pkthdr *packet_header, const u_char *packet) {
    struct ip *ip_header = (struct ip *)(packet + 14);
    struct udphdr *udp_header = (struct udphdr *)(packet + 14 + ip_header->ip_hl * 4);
    // Check if the packet is a DNS query
    if (ntohs(udp_header->uh_dport) == dns_port) {
        if (debug_level > 0) {
            std::cout << "DNS query from: " << inet_ntoa(ip_header->ip_src) << std::endl;
        }
        // Create a UDP socket to send the DNS response
        int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd < 0) {
            std::cerr << "Socket creation failed: " << strerror(errno) << std::endl;
            return;
        }

        // Bind the socket to the DNS port
        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = inet_addr(server_ip.c_str());
        server_addr.sin_port = htons(dns_port);
        if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            std::cerr << "Bind failed: " << strerror(errno) << std::endl;
            close(sockfd);
            return;
        }
        // Set the client address
        struct sockaddr_in client_addr;
        client_addr.sin_family = AF_INET;
        client_addr.sin_port = udp_header->uh_sport;
        client_addr.sin_addr = ip_header->ip_src;
        // Extract the DNS transaction ID
        int dns_header_offset = 14 + ip_header->ip_hl * 4 + sizeof(struct udphdr);
        uint16_t transaction_id = ntohs(*(uint16_t *)(packet + dns_header_offset));
        // Print the requested domain and transaction ID to debug
        if (debug_level > 0) {
            std::cout << "Received DNS query: " << inet_ntoa(client_addr.sin_addr) << std::endl;
            if (debug_level > 1) {
                std::cout << "Requested domain: ";
                for (int i = 0; i < ntohs(udp_header->uh_ulen) - sizeof(struct udphdr); i++) {
                    std::cout << packet[dns_header_offset + sizeof(uint16_t) + i];
                }
                std::cout << std::endl;
                std::cout << "Transaction ID: " << transaction_id << std::endl;
                if (debug_level > 2) {
                    std::cout << "Received packet (first 64 bytes): ";
                    for (int i = 0; i < 64 && i < packet_header->caplen; i++) {
                        std::cout << std::hex << (int)packet[i] << " ";
                    }
                    std::cout << std::dec << std::endl;
                }
            }
        }
        // Handle DNS query
        // check cache for the requested domain
        std::string domain = "";
        for (int i = 0; i < ntohs(udp_header->uh_ulen) - sizeof(struct udphdr); i++) {
            domain += packet[dns_header_offset + sizeof(uint16_t) + i];
        }
        std::vector<uint8_t> response;
        if (cache.getEntry(domain, response)) {
            // if found, send the cached response
            send_dns_response(sockfd, &client_addr, sizeof(client_addr), response.data(), response.size(), transaction_id);
            if (debug_level > 1) {
                std::cout << "Resolved from cache" << std::endl;
            }
        } else {
            // if not found, query the upstream DNS server and cache the response
            // Create a UDP socket to send the DNS query
            int dns_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
            if (debug_level > 1) {
                std::cout << "Querying upstream DNS server" << std::endl;
            }
            if (dns_sockfd < 0) {
                std::cerr << "Socket creation failed: " << strerror(errno) << std::endl;
                close(sockfd);
                return;
            }
            // Set the upstream DNS server address
            struct sockaddr_in dns_server_addr;
            dns_server_addr.sin_family = AF_INET;
            dns_server_addr.sin_addr.s_addr = inet_addr(upstream_dns.c_str());
            dns_server_addr.sin_port = htons(53);
            // Send the DNS query
            int result = sendto(dns_sockfd, packet + 14 + ip_header->ip_hl * 4, ntohs(udp_header->uh_ulen) - sizeof(struct udphdr), 0, (struct sockaddr *)&dns_server_addr, sizeof(dns_server_addr));
            if (result < 0) {
                std::cerr << "Failed to send DNS query: " << strerror(errno) << std::endl;
                close(sockfd);
                close(dns_sockfd);
                return;
            }
            // Receive the DNS response
            u_char response_buffer[BUFFER_SIZE];
            socklen_t addr_len = sizeof(dns_server_addr);
            result = recvfrom(dns_sockfd, response_buffer, BUFFER_SIZE, 0, (struct sockaddr *)&dns_server_addr, &addr_len);
            if (result < 0) {
                std::cerr << "Failed to receive DNS response: " << strerror(errno) << std::endl;
                close(sockfd);
                close(dns_sockfd);
                return;
            }
            // Close the DNS socket
            close(dns_sockfd);
            // Cache the response
            cache.addEntry(domain, std::vector<uint8_t>(response_buffer, response_buffer + result));
            if (debug_level > 1) {
                std::cout << "Resolved from Upstream DNS server: Cached response" << std::endl;
            }
            // Send the DNS response
            send_dns_response(sockfd, &client_addr, sizeof(client_addr), response_buffer, result, transaction_id);
            if (debug_level > 1) {
                std::cout << "Sent DNS response" << std::endl;
            }
        }
        close(sockfd);
    }
}

void send_dns_response(
    int sockfd, 
    struct sockaddr_in *client_addr, 
    socklen_t addr_len, 
    const u_char *response, 
    int response_len, 
    uint16_t transaction_id) 
{
    // Set the DNS response ID to match the transaction ID
    u_char modified_response[BUFFER_SIZE];
    memcpy(modified_response, response, response_len);

    // The transaction ID is located at the beginning of the DNS header
    // which is typically after the IP and UDP headers
    // Assuming no IP options, the offset is 0
    int dns_header_offset = 0; // DNS header starts at the beginning of the response
    *(uint16_t *)(modified_response + dns_header_offset) = htons(transaction_id);

    if (debug_level > 1) {
        std::cout << "sending response with transaction id: " << transaction_id << std::endl;
        
        if (debug_level > 2) {
            std::cout << "Modified response (first 64 bytes): ";
            for (int i = 0; i < 64 && i < response_len; i++) {
                std::cout << std::hex << (int)modified_response[i] << " ";
            }
            std::cout << std::dec << std::endl;
        }
    }

    int result = sendto(sockfd, modified_response, response_len, 0, (struct sockaddr *)client_addr, addr_len);
    if (result < 0) {
        std::cerr << "Failed to send response: " << strerror(errno) << std::endl;
    } else if (debug_level > 1) {
        // Extract the resolved IP address from the response
        struct in_addr resolved_ip;
        memcpy(&resolved_ip, modified_response + dns_header_offset + 12, sizeof(struct in_addr));
        std::cout << "Resolved IP: " << inet_ntoa(resolved_ip) << std::endl;
    }
}

int main() {
    // load the configuration from the yaml file
    loadConfig();
    std::cout << "Server IP: " << server_ip << std::endl;
    std::cout << "Upstream DNS: " << upstream_dns << std::endl;
    std::cout << "Interface: " << interface << std::endl;
    std::cout << "DNS Port: " << dns_port << std::endl;
    std::cout << "Debug Level: " << debug_level << std::endl;

    cache = DnsCache();

    // set up the signal handler for program shutdown
    struct sigaction sigIntHandler;
    sigIntHandler.sa_handler = [](int s) {
        std::cout << "Shutting down..." << std::endl;
        exit(0);
    };
    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_flags = 0;
    sigaction(SIGINT, &sigIntHandler, nullptr);

    // open the network interface
    char errbuf[PCAP_ERRBUF_SIZE];
    // interface set in the yaml file
    pcap_t *handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Couldn't open device: " << errbuf << std::endl;
        return 1;
    }
    // create the filter to capture only DNS packets
    struct bpf_program fp;
    std::string filter_exp = "udp dst port " + std::to_string(dns_port);
    if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Couldn't parse filter: " << pcap_geterr(handle) << std::endl;
        return 1;
    }
    // set the filter
    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Couldn't install filter: " << pcap_geterr(handle) << std::endl;
        return 1;
    }
    // start capturing packets
    pcap_loop(handle, 0, process_packet, nullptr);

    // program ending, close the handle
    pcap_close(handle);
    return 0;
}
