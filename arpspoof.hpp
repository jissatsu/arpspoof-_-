#ifndef __ARPSPOOF_H
#define __ARPSPOOF_H 1

#include <iostream>
#include <stdio.h>
#include <stdint.h>
#include <netinet/ether.h>
#include <libnet.h>
#include <getopt.h>
#include "net.h"

#ifndef ARP_CACHE 
    #define ARP_CACHE "/proc/net/arp"
#endif

struct arp_ctx
{
    uint8_t src_hw[6];  // source hardware addr
    uint8_t src_ip[4];  // source ip addr
    uint8_t dst_hw[6];  // target hardware addr
    uint8_t dst_ip[4];  // target ip addr
};

// arpspoof context
struct arpspf_ctx
{
    char *iface;           // interface
    uint8_t target_ip[4];  // arpspoof target
    uint8_t host_ip[4];    // arpspoof host
};

namespace killua
{
    libnet_t       * __init__( char *iface );
    struct arp_ctx * format_arp( libnet_t *ltag, uint8_t *src_hw, uint8_t *src_ip, uint8_t *dst_hw, uint8_t *dst_ip );

    void   __die( libnet_t *ltag, const char *msg );
    short  arp_packet( libnet_t *ltag, struct arp_ctx *ctx, char *errbuf );
    short  lookup_arp( char *ip, uint8_t *hw );
    int    inject_arp( libnet_t *ltag );
}

#endif
