#include "arpspoof.h"

void arpspoof( struct net *_net, struct spoof_endpoints *_spf )
{
    libnet_t *lt;
    uint8_t src_ip[4];
    struct endpoint _endps[_net->hosts_range];
    struct libnet_ether_addr *hw;

    if ( !(lt = libnet_init( LIBNET_LINK, _net->iface, arpspoof_errbuf )) ) {
        __die( arpspoof_errbuf );
    }

    if ( !(hw = libnet_get_hwaddr( lt )) ) {
        __die( libnet_geterror( lt ) );
    }
    
    if ( !_spf->target )
    {
        printf( "\n%s[!]%s Target not specified!\n", RED, NLL );
        printf( "%s[+]%s Refreshig arp table!\n",    GRN, NLL );
        printf( "%s[+]%s Probing network!\n\n",      GRN, NLL );

        cnvrt_ip2b( _net->ip, src_ip );
        for ( int i = 1 ; i < _net->hosts_range ; i++ )
        {
            uint8_t *ip = long2ip( _net->start_ip + i );
            arp_inject(
                lt, ARPOP_REQUEST, hw->ether_addr_octet, src_ip, (uint8_t *) "\xff\xff\xff\xff\xff\xff", ip
            );
            sleep( 1 );
        }
    }

    if ( lookup_arp( _net->iface, _endps ) < 0 ) {
        __die( arpspoof_errbuf );
    }
}