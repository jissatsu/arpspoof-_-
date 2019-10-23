#include "arp.h"

void arp_inject( libnet_t *ltag, uint16_t opcode, 
                  uint8_t *src_hw, uint8_t *src_ip,
                  uint8_t *dst_hw, uint8_t *dst_ip ) 
{
    libnet_ptag_t ether, arp;

    // arp header
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

    // ethernet header
    ether = libnet_autobuild_ethernet( dst_hw, ETHERTYPE_ARP, ltag );
    if ( ether < 0 ){
        __die( "Ethernet header error!" );
    }

    if ( libnet_write( ltag ) < 0 ) {
        __die( libnet_geterror( ltag ) );
    }

    if ( opcode == ARPOP_REQUEST ){
        printf( 
            "\r%s[?]%s Who has %d.%d.%d.%d? Tell %d.%d.%d.%d ", 
            GRN, NLL,
            dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3], 
            src_ip[0], src_ip[1], src_ip[2], src_ip[3]
        );
    } else {
        printf( "%s[+]%s %d.%d.%d.%d is at %02x:%02x:%02x:%02x:%02x:%02x\n", 
            GRN, NLL,
            src_ip[0], src_ip[1], src_ip[2], src_ip[3],
            src_hw[0], src_hw[1], src_hw[2], src_hw[3], src_hw[4], src_hw[5]
        );
    }
    fflush( stdout );
    libnet_clear_packet( ltag );
}

short lookup_arp( char *iface, struct endpoint *endps )
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
        sprintf( arpspoof_errbuf, "lookup_arp(): %s", strerror( errno ) );
        return -1;
    }

    live_hosts = 0;
    while ( fgets( line, 0xFF, fp ) )
    {
        sscanf( line, "%s %s %s %s %s %s", addr, hwtype, flags, hwaddr, mask, dev );
        if ( strcmp( iface, dev ) != 0 ) {
            continue;
        }
        memcpy( endps->host_ip,     addr,   strlen( addr )   + 1 );
        memcpy( (endps++)->host_hw, hwaddr, strlen( hwaddr ) + 1 );
        ++live_hosts;
    }
    fseek( fp, 0, SEEK_SET );
    return 0;
}