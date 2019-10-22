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

struct host
{
    unsigned int is_gateway : 1;
    char *host_ip;
    char *host_hw;
};

struct arp_ctx
{
    uint8_t src_hw[6];  // source hardware addr
    uint8_t src_ip[4];  // source ip addr
    uint8_t dst_hw[6];  // target hardware addr
    uint8_t dst_ip[4];  // target ip addr
};

short lookup_arp( char *ip, uint8_t *hw );

#endif