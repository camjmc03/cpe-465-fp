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

#define BUFFER_SIZE 512

std::string server_ip;
std::string upstream_dns;
std::string interface;
int dns_port;
int debug_level;

void loadConfig() {
    YAML::Node config = YAML::LoadFile("config.yaml");
    server_ip = config["server_ip"].as<std::string>();
    upstream_dns = config["upstream_dns"].as<std::string>();
    interface = config["interface"].as<std::string>();
    dns_port = config["dns_port"].as<int>();
    debug_level = config["debug_level"].as<int>();
}

void process_packet(u_char *user, const struct pcap_pkthdr *packet_header, const u_char *packet);
void send_dns_response(int sockfd, struct sockaddr_in *client_addr, socklen_t addr_len, const u_char *request, int request_len);

void process_packet(u_char *user, const struct pcap_pkthdr *packet_header, const u_char *packet) {
    struct ip *ip_header = (struct ip *)(packet + 14);
    struct udphdr *udp_header = (struct udphdr *)(packet + 14 + ip_header->ip_hl * 4);
    // Check if the packet is a DNS query
    if (ntohs(udp_header->uh_dport) == dns_port) {
        if (debug_level > 0) {
            std::cout << "DNS query from: " << inet_ntoa(ip_header->ip_src) << std::endl;
        }
        // Create a raw socket to send the DNS response
        int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        if (sockfd < 0) {
            std::cerr << "Socket creation failed" << std::endl;
            return;
        }

        struct sockaddr_in client_addr;
        client_addr.sin_family = AF_INET;
        client_addr.sin_port = udp_header->uh_sport;
        client_addr.sin_addr = ip_header->ip_src;
        // Send the DNS response
        if (debug_level > 0) {
            std::cout << "Sending DNS response to: " << inet_ntoa(client_addr.sin_addr) << std::endl;
        }
        send_dns_response(
            sockfd, 
            &client_addr, 
            sizeof(client_addr), 
            packet + 14 + ip_header->ip_hl * 4 + sizeof(struct udphdr), 
            ntohs(udp_header->uh_ulen) - sizeof(struct udphdr));

        close(sockfd);
    }
}

void send_dns_response(
    int sockfd, 
    struct sockaddr_in *client_addr, 
    socklen_t addr_len, 
    const u_char *request, 
    int request_len ) 
    {
    u_char response[BUFFER_SIZE];
    int result = 0;
    memcpy(response, request, request_len);
    
    // Modify the response as needed (e.g., set the QR bit to 1, add answer section, etc.)
    result = sendto(sockfd, response, request_len, 0, (struct sockaddr *)client_addr, addr_len);
    if (0 > result) {
        std::cerr << "Failed to send response" << std::endl;
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
