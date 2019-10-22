#include "arp.h"

void arp_inject( libnet_t *ltag, uint16_t opcode, 
                  uint8_t *src_hw, uint8_t *src_ip,
                  uint8_t *dst_hw, uint8_t *dst_ip ) 
{
    libnet_ptag_t ether, arp;

    arp = libnet_autobuild_arp(
        opcode,
        src_hw,
        src_ip,
        dst_hw,
        dst_ip,
        ltag
    );
    if ( arp < 0 ){
        __die( "Arp header error!" );
    }

    ether = libnet_autobuild_ethernet(
        dst_hw,
        ETHERTYPE_ARP,
        ltag
    );
    if ( ether < 0 ){
        __die( "Ethernet header error!" );
    }    

    if ( libnet_write( ltag ) < 0 ) {
        __die( libnet_geterror( ltag ) );
    }
    libnet_clear_packet( ltag );
}

short lookup_arp( struct endpoint *endps )
{
    FILE *fp;
    char line[0xFF];
    char addr[20];
    char hwtype[5];
    char flags[5];
    char hwaddr[25];
    char mask[5];
    char dev[25];

    if ( !(fp = fopen( ARP_CACHE, "r" )) ){
        return -1;
    }
    while ( fgets( line, 0xFF, fp ) ){
        sscanf( line, "%s %s %s %s %s %s", addr, hwtype, flags, hwaddr, mask, dev );
    }
    fseek( fp, 0, SEEK_SET );
    return 0;
}