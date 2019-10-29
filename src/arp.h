#ifndef __ARPH_H
#define __ARPH_H 1

#include <stdio.h>
#include <stdint.h>
#include <netinet/ether.h>
#include <libnet.h>
#include <pcap.h>
#include <net/if_arp.h>
#include <pthread.h>
#include <getopt.h>
#include "net.h"
#include "sleep.h"
#include "output.h"

#ifndef ARP_CACHE 
    #define ARP_CACHE "/proc/net/arp"
#endif

// libnet context
libnet_t *lt;

// number of live hosts on the network
uint16_t live_hosts;

// broadcast destination hardware addr
static uint8_t bcast_hw[] = "\xff\xff\xff\xff\xff\xff";

struct arpspf_eth_hdr
{
    uint8_t dst_hw[6];
    uint8_t src_hw[6];
    uint16_t eth_type;
};

struct arpspf_arp_hdr
{
    uint16_t hwtype;
    uint16_t ptype;
    uint8_t  hwlen;
    uint8_t  ptlen;
    uint16_t opcode;
    uint8_t  src_hw[6];
    uint8_t  src_ip[4];
    uint8_t  dst_hw[6];
    uint8_t  dst_ip[4];
};

struct endpoint
{
    char host_ip[25];
    char host_hw[25];
    uint8_t bhost_ip[4];
    uint8_t bhost_hw[6];
}
_endps[65534];

void * arp_receiver( void *conf );
void   arp_refresh( struct net *_net );
void   arp_inject( libnet_t *ltag, struct arpspf_eth_hdr *eth, struct arpspf_arp_hdr *arp );
void   probe_endpoint( char *endpt, struct net *_net );
void   packet_handler( u_char *args, const struct pcap_pkthdr *header, const u_char *packet );

short arp_add_entry( char *iface, uint8_t *ip, uint8_t *hw );
short lookup_arp( char *iface, char *ip_addr, char *hw_addr );

struct arpspf_eth_hdr * build_eth_hdr( char *dst_hw, char *src_hw );
struct arpspf_arp_hdr * build_arp_hdr( uint16_t opcode, char *dst_hw, char *dst_ip, char *src_hw, char *src_ip );

#endif