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
uint16_t live_hosts;

struct endpoint
{
    unsigned int is_gateway : 1;
    char *host_ip;
    char *host_hw;
};

void  arp_inject( libnet_t *ltag, uint16_t opcode, uint8_t *src_hw, uint8_t *src_ip, uint8_t *dst_hw, uint8_t *dst_ip );
short lookup_arp( struct endpoint *endps );

#endif