#ifndef ARP_H
#define ARP_H

#endif // ARP_H

#include <netinet/if_ether.h>
#include "ip.h"

#pragma pack(push, 1)
struct ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};
#pragma pack(pop)

#pragma pack(push, 1)
struct arp_hdr {
    uint16_t hrd_; /*hardware type*/
    uint16_t pro_; /*protocol*/
    uint8_t  hln_; /*hardware size*/
    uint8_t  pln_; /*protocol size*/
    uint16_t op_; /*opcode*/
    u_char smac[ETHER_ADDR_LEN]; /*sender mac address*/
    Ip sip; /*sender ip address*/
    u_char tmac[ETHER_ADDR_LEN]; /*target mac address*/
    Ip tip; /*target ip address*/
};
#pragma pack(pop)
