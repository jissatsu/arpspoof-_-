#ifndef __ARPSPOOF_H
#define __ARPSPOOF_H 1

#include <iostream>
#include <stdint.h>
#include <netinet/ether.h>
#include <libnet.h>
#include <getopt.h>

// arpspoof error buffer
static char arpsf_errbuf[0xFF];

// arpspoof context
struct arpsf_ctx
{
    uint8_t target[4];    // target ip addr
    uint8_t host[4];      // host ip addr
    uint8_t target_hw[6]; // target hardware addr
    uint8_t src_hw[6];    // source hardware addr
};

namespace killua
{
    void cnvrt_ip2b( char *ip, uint8_t *dst );
    void arpsf_packet( libnet_t *ltag, struct arpsf_ctx *ctx );
    void arpspoof( struct arpsf_ctx *ctx, char *iface );
    void arpspoof_initiate( libnet_t *ltag, struct arpsf_ctx *ctx );
    void __die( libnet_t *ltag, const char *msg );
}

#endif
