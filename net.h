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

typedef enum { IPV4, MASK } addr_num_t;

struct net
{
    char *iface;           // network interface
    char nmask[20];        // netmask
    char ip[20];           // ip of device
    uint32_t hosts_range;  // network range
    uint32_t start_ip;     // start ip address i.e 192.168.0.1
};

uint32_t ip2long( char *ip );
uint32_t calc_hosts( struct net *_net );

void   init_net( char *iface, struct net *_net );
short  cnvrt_ip2b( char *ip, uint8_t *dst );
short  cnvrt_hw2b( char *hw, uint8_t *dst );
short  is_ipv4_format( char *ip );
short  is_hw_format( char *hw );
short  dev_addr( char *iface, char *dst, addr_num_t type, char *errbuf );

#endif