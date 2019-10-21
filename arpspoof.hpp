#ifndef __ARPSPOOF_H
#define __ARPSPOOF_H 1

#include <iostream>
#include <stdio.h>
#include <stdint.h>
#include <netinet/ether.h>
#include <libnet.h>
#include <getopt.h>
#include "addr.h"

#ifndef ARP_CACHE 
    #define ARP_CACHE "/proc/net/arp"
#endif

struct arp_ctx
{
    short opcode;
    uint8_t src_hw[6];  // source hardware addr
    uint8_t src_ip[4];  // source ip addr
    uint8_t dst_hw[6];  // target hardware addr
    uint8_t dst_ip[4];  // target ip addr
};

// arpspoof context
struct arpspf_ctx
{
    char *iface;   // interface
    char *target;  // arpspoof target
    char *host;    // arpspoof host
};

namespace killua
{
    libnet_t       * __init__( char *iface );
    struct arp_ctx * format_arp( libnet_t *ltag, uint16_t opcode, uint8_t *src_hw, uint8_t *src_ip, uint8_t *dst_hw, uint8_t *dst_ip );

    void   arp_packet( libnet_t *ltag, struct arp_ctx *ctx );
    void   __die( libnet_t *ltag, const char *msg );
    short  lookup_arp( char *ip, uint8_t *hw );
    short  arpspoof( struct arpspf_ctx *conf, char *errbuf );
    int    inject_arp( libnet_t *ltag );
}

#endif
