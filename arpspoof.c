#include "arpspoof.h"

void arpspoof( struct net *_net, struct spoof_endpoints *_spf )
{
    struct endpoint _endps[_net->hosts_range];

    if ( lookup_arp( _net->iface, _endps ) < 0 ) {
        __die( arpspoof_errbuf );
    }

    fprintf( stdout, "%s\n", _endps[0].host_ip );
    fprintf( stdout, "%s\n", _endps[0].host_hw );
}