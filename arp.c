#include "arp.h"

short arp_packet( libnet_t *ltag, struct arp_ctx *ctx, 
                         char *errbuf )
{
    libnet_ptag_t ether, arp;

    arp = libnet_autobuild_arp(
        ARPOP_REPLY,
        ctx->src_hw,
        ctx->src_ip,
        ctx->dst_hw,
        ctx->dst_ip,
        ltag
    );
    if ( arp < 0 )
        sprintf( errbuf, "%s", "Arp header error!" );
        return -1;
    
    ether = libnet_autobuild_ethernet(
        ctx->dst_hw,
        ETHERTYPE_ARP,
        ltag
    );
    if ( ether < 0 )
        sprintf( errbuf, "%s", "Ethernet header error!" );
        return -1;
}

short lookup_arp( char *ip, uint8_t *hw )
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
        if ( strcmp( addr, ip ) == 0 ) {
            break;
        }
    }
    fseek( fp, 0, SEEK_SET );
    if ( strlen( hwaddr ) > 0 && is_hw_format( hwaddr ) == 0 ) {
        cnvrt_hw2b( hwaddr, hw );
        return 0;
    }
    return -1;
}