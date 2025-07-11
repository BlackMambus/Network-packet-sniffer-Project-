#include <pcap.h>
#include <iostream>
#include <winsock2.h> // For Windows IP address conversion
#include <ws2tcpip.h>

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")

// Ethernet headers are always exactly 14 bytes
#define ETHERNET_HEADER_LEN 14

// IP header
struct ip_header {
    u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;            // Type of service 
    u_short tlen;           // Total length 
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Protocol
    u_short crc;            // Header checksum
    u_char  saddr[4];       // Source address
    u_char  daddr[4];       // Destination address
};

// Callback function invoked for every captured packet
void packetHandler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    const ip_header* ih;
    ih = (ip_header*)(pkt_data + ETHERNET_HEADER_LEN);

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, ih->saddr, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, ih->daddr, dst_ip, sizeof(dst_ip));

    std::cout << "📦 Packet captured: " << header->len << " bytes\n";
    std::cout << "   From: " << src_ip << " --> To: " << dst_ip << "\n";
}

int main() {
    pcap_if_t* alldevs;
    pcap_if_t* dev;
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Find all devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << "\n";
        return 1;
    }

    // Use the first device
    dev = alldevs;
    if (!dev) {
        std::cerr << "No devices found.\n";
        return 1;
    }

    std::cout << "Using device: " << dev->name << "\n";

    // Open the device for sniffing
    handle = pcap_open_live(dev->name, 65536, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "Unable to open device: " << errbuf << "\n";
        return 1;
    }

    // Start packet capture loop
    pcap_loop(handle, 10, packetHandler, nullptr); // Capture 10 packets

    pcap_close(handle);
    pcap_freealldevs(alldevs);

    return 0;
}



