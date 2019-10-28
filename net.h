#ifndef __ADDR_H
#define __ADDR_H 1

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <errno.h>
#include "error.h"

// address types
typedef enum { IPV4, MASK } addr_num_t;

struct net
{
    char *iface;           // network interface
    char nmask[25];        // netmask
    char ip[25];           // ip of device
    char hw[35];           // hardware addr of device
    short subnet;          // subnet -> /16; /17; /24 etc...
    uint32_t hosts_range;  // network range
    uint32_t start_ip;     // start ip address i.e 192.168.0.1
}
_net;

short     calc_subnet( char *nmask );
uint8_t * long2ip( uint32_t _long );
uint32_t  ip2long( char *ip );
uint32_t  calc_hosts( char *ip, char *nmask );
uint32_t  net_off( char *ip, char *nmask  );

char * cnvrt_ipb2str( uint8_t *ip );
short  cnvrt_ip2b( char *ip, uint8_t *dst );
short  cnvrt_hw2b( char *hw, uint8_t *dst );
short  is_ipv4_format( char *ip );
short  is_hw_format( char *hw );
short  dev_addr( char *iface, char *dst, addr_num_t type, char *errbuf );

#endif