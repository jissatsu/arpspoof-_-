#include "arpspoof.h"

short __init_arpspoof__( char *iface, struct net *_net )
{   
    struct libnet_ether_addr *hw;
    if ( !(lt = libnet_init( LIBNET_LINK, iface, arpspoof_errbuf )) ) {
        return -1;
    }

    // hardware address of device
    if ( !(hw = libnet_get_hwaddr( lt )) ) {
        sprintf( arpspoof_errbuf, "%s", libnet_geterror( lt ) );
        return -1;
    }
    
    sprintf( 
        _net->hw, "%02x:%02x:%02x:%02x:%02x:%02x",
            hw->ether_addr_octet[0],
            hw->ether_addr_octet[1],
            hw->ether_addr_octet[2],
            hw->ether_addr_octet[3],
            hw->ether_addr_octet[4],
            hw->ether_addr_octet[5]
    );

    if ( dev_addr( iface, _net->ip, IPV4, arpspoof_errbuf ) < 0 ) {
        return -1;
    }
    if ( dev_addr( iface, _net->nmask, MASK, arpspoof_errbuf ) < 0 ) {
        return -1;
    }
    
    _net->iface       = iface;
    _net->hosts_range = calc_hosts( _net->ip, _net->nmask );
    _net->start_ip    = net_off(    _net->ip, _net->nmask );
    _net->subnet      = calc_subnet( _net->nmask );
    return 0;
}

short arp_receiver_start( struct net *_net )
{
    int err;
    pthread_t thread;
    
    err = pthread_create(
        &thread,
        NULL,
        arp_receiver,
        (void *) _net
    );

    if ( err < 0 ) {
        sprintf( 
            arpspoof_errbuf, 
            "Error spawning arp_receiver() thread!\n" 
        );
        return -1;
    }
    printf( "%s[+]%s Arp receiver started successfully!\n", GRN, NLL );
    return 0;
}

void list_targets( struct endpoint *_entps )
{
    for ( register int i = 0 ; i < live_hosts ; i++ ) {
        printf( "%s[-]%s %s\n", GRN, NLL, (_entps++)->host_ip );
    }
}

void arpspoof( struct net *_net, struct spoof_endpoints *_spf )
{
    int refresh_stat;
    char target[25];
    struct endpoint _endps[_net->hosts_range];
        
    refresh_stat = 0;

    if ( arp_receiver_start( _net ) < 0 ) {
        __die( arpspoof_errbuf );
    }

    if ( !_spf->target ){
        printf( "\n" );
        printf( "%s[!]%s Target not specified!\n", RED, NLL );
        printf( "%s[+]%s Refreshig arp table...\n",  GRN, NLL );
        arp_refresh( lt, _net );

        if ( lookup_arp( _net->iface, _endps ) < 0 ) {
            __die( arpspoof_errbuf );
        }
        printf( "%s[+]%s Listing targets...\n\n", GRN, NLL );
        list_targets( _endps );

        printf( "Choose a target to poison: " );
        scanf( "%s", target );
    } 
    else {
        strcpy( target, _spf->target );
    }

    printf( "%s\n", target );

    // SIGTSTP
    // SIGINT
    // SIGTERM
}