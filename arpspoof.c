#include "arpspoof.h"

void arpspoof( struct net *_net, struct spoof_endpoints *_spf )
{
    libnet_t *lt;
    struct endpoint _endps[_net->hosts_range];
    struct libnet_ether_addr *hw;

    if ( !(lt = libnet_init( LIBNET_LINK, _net->iface, arpspoof_errbuf )) ) {
        __die( arpspoof_errbuf );
    }

    if ( !(hw = libnet_get_hwaddr( lt )) ) {
        __die( libnet_geterror( lt ) );
    }
    
    if ( lookup_arp( _net->iface, _endps ) < 0 ) {
        __die( arpspoof_errbuf );
    }
}