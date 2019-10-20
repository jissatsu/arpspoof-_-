#include "arpspoof.hpp"


void killua::cnvrt_ip2b( char *ip, uint8_t *dst )
{
    register int i, j;
    char frag[4];
    uint8_t dst_ip[4];

    i = 0;
    j = 0;
    
    while ( *ip != '\0' )
    {
        if ( *ip == '.' ) {
            frag[i] = '\0', dst_ip[j++] = atoi( frag ), i = 0, ip++;
        }
        frag[i++] = *ip++;
    }
    
    frag[i] = '\0';
    dst_ip[j] = atoi( frag );
    memcpy( dst, dst_ip, 4 );
}


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

void killua::format_arp( libnet_t *ltag, struct arp_ctx *ctx )
{
    
}

int killua::lookup_arp( char *ip )
{
    FILE *fp;

    if ( !(fp = fopen( ARP_CACHE, "r" )) )
        return -1;
        
    return 0;
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

void killua::arpspoof( char *iface, char *target, char *host )
{
    libnet_t *ltag;
    struct libnet_ether_addr *hw_addr;
    struct arp_ctx *ctx;
    
    if ( !(ltag = libnet_init(LIBNET_LINK, iface, arpsf_errbuf)) )
        killua::__die( NULL, arpsf_errbuf );
    
    if ( !(hw_addr = libnet_get_hwaddr( ltag )) )
        killua::__die( ltag, libnet_geterror( ltag ) );
}

void killua::__die( libnet_t *ltag, const char *msg )
{
    std::cerr << msg << std::endl;
    if ( ltag )
        libnet_destroy( ltag );
    exit( 2 );
}