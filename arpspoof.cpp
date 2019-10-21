#include "arpspoof.hpp"


void killua::arp_packet( libnet_t *ltag, struct arp_ctx *ctx )
{
    libnet_ptag_t ether, arp;

    arp = libnet_autobuild_arp(
        ctx->opcode,
        ctx->src_hw,
        ctx->src_ip,
        ctx->dst_hw,
        ctx->dst_ip,
        ltag
    );
    if ( arp < 0 )
        killua::__die( ltag, "Arp header error!" );
    
    ether = libnet_autobuild_ethernet(
        ctx->dst_hw,
        ETHERTYPE_ARP,
        ltag
    );
    if ( ether < 0 )
        killua::__die( ltag, "Ethernet header error" );
}

struct arp_ctx * killua::format_arp( libnet_t *ltag, uint16_t opcode,
                                     uint8_t *src_hw,
                                     uint8_t *src_ip,
                                     uint8_t *dst_hw,
                                     uint8_t *dst_ip )
{
    static struct arp_ctx ctx;
    if ( opcode != ARPOP_REQUEST && opcode != ARPOP_REPLY )
        return NULL;
    
    ctx.opcode = opcode;
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
    if ( strlen( hwaddr ) > 0 ) {
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

short killua::arpspoof( struct arpspf_ctx *conf, char *errbuf )
{
    libnet_t *ltag;
    struct libnet_ether_addr *hw;
    struct arp_ctx *ctx;
    uint8_t lkup_host[6];
    uint8_t lkup_target[6];

    if ( !(ltag = libnet_init(LIBNET_LINK, conf->iface, errbuf)) ) {
        return -1;
    }

    if ( !(hw = libnet_get_hwaddr( ltag )) ) {
        sprintf( errbuf, "%s\n", libnet_geterror( ltag ) );
        return -1;
    }

    // dev_addr( conf->iface, ipaddr, errbuf );
    if( killua::lookup_arp( conf->host, lkup_host ) < 0 ){
        fprintf( stdout, "No host" );
    } else {
        fprintf( stdout, "%02x:%02x:%02x:%02x:%02x:%02x\n", lkup_host[0], lkup_host[1], lkup_host[2], lkup_host[3], lkup_host[4], lkup_host[5] );
    }

    if( killua::lookup_arp( conf->target, lkup_target ) < 0 ){
        fprintf( stdout, "No target" );
    } else {
        fprintf( stdout, "%02x:%02x:%02x:%02x:%02x:%02x\n", lkup_target[0], lkup_target[1], lkup_target[2], lkup_target[3], lkup_target[4], lkup_target[5] );
    }
    return 0;
}

void killua::__die( libnet_t *ltag, const char *msg )
{
    std::cerr << msg << std::endl;
    if ( ltag )
        libnet_destroy( ltag );
    exit( 2 );
}