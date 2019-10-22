#ifndef __ARPH_H
#define __ARPH_H 1

#include <stdio.h>
#include <stdint.h>
#include <netinet/ether.h>
#include <libnet.h>
#include <getopt.h>
#include "net.h"

#ifndef ARP_CACHE 
    #define ARP_CACHE "/proc/net/arp"
#endif

// number of live hosts on the network
uint32_t live_hosts;

struct endpoint
{
    unsigned int is_gateway : 1;
    char *host_ip;
    char *host_hw;
};

struct arp_ctx
{
    uint16_t opcode;    // arp opcode
    uint8_t src_hw[6];  // source hardware addr
    uint8_t src_ip[4];  // source ip addr
    uint8_t dst_hw[6];  // target hardware addr
    uint8_t dst_ip[4];  // target ip addr
};

short lookup_arp( struct endpoint *_ent );

#endif