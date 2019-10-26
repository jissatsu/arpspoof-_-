#include "arp.h"

void arp_inject( libnet_t *ltag, uint16_t opcode, 
                 uint8_t *src_hw, uint8_t *src_ip,
                 uint8_t *dst_hw, uint8_t *dst_ip ) 
{
    libnet_ptag_t ether, arp;
    char *frmt_src = NULL;
    char *frmt_dst = NULL;

    // arp header
    arp = libnet_autobuild_arp(
        opcode,
        src_hw,
        src_ip,
        dst_hw,
        dst_ip,
        ltag
    );
    if ( arp < 0 ){
        __die( "Arp header error!" );
    }

    // ethernet header
    ether = libnet_autobuild_ethernet( dst_hw, ETHERTYPE_ARP, ltag );
    if ( ether < 0 ){
        __die( "Ethernet header error!" );
    }

    if ( libnet_write( ltag ) < 0 ) {
        __die( libnet_geterror( ltag ) );
    }

    frmt_dst = cnvrt_ipb2str( dst_ip );
    frmt_src = cnvrt_ipb2str( src_ip );

    if ( opcode == ARPOP_REQUEST ){
        printf( "\r%s[?]%s Who has %s? Tell %s ", GRN, NLL, frmt_dst, frmt_src );
    } 
    else {
        printf( "%s[+]%s %s is at %02x:%02x:%02x:%02x:%02x:%02x\n", 
            GRN, NLL, frmt_src,
            src_hw[0], src_hw[1], src_hw[2], 
            src_hw[3], src_hw[4], src_hw[5]
        );
    }
    fflush( stdout );
    free( frmt_src );
    free( frmt_dst );
    libnet_clear_packet( ltag );
}

/* refresh the arp cache */
void arp_refresh( struct net *_net )
{
    char *dst_ip;

    for ( uint32_t i = 1 ; i < _net->hosts_range ; i++ )
    {
        dst_ip = cnvrt_ipb2str( long2ip( _net->start_ip + i ) );
        probe_endpoint( dst_ip, _net );
        free( dst_ip );
    }
    printf( "\n" );
}

void probe_endpoint( char *endpt, struct net *_net )
{   
    uint8_t endpoint_ip[4];
    uint8_t src_ip[4];
    uint8_t src_hw[6];

    cnvrt_ip2b( endpt, endpoint_ip );
    cnvrt_ip2b( _net->ip, src_ip );
    cnvrt_hw2b( _net->hw, src_hw );

    // skip gratuitous arp
    if ( endpoint_ip[0] == src_ip[0]
      && endpoint_ip[1] == src_ip[1]
      && endpoint_ip[2] == src_ip[2]
      && endpoint_ip[3] == src_ip[3] ) {
          return;
    }
    arp_inject(
        lt, ARPOP_REQUEST, src_hw, src_ip, bcast_hw, endpoint_ip
    );
    mssleep( 0.2 );
}

void packet_handler( u_char *args, const struct pcap_pkthdr *header, 
                     const u_char *packet )
{
    struct net *_net = (struct net *) args;
    struct arpspf_eth_hdr *eth_hdr = (struct arpspf_eth_hdr *) packet;
    struct arpspf_arp_hdr *arp_hdr = (struct arpspf_arp_hdr *) (packet + 14);

    uint16_t eth_type;
    uint16_t opcode;

    eth_type = ntohs( eth_hdr->eth_type );
    opcode   = ntohs( arp_hdr->opcode );

    if ( eth_type == ETHERTYPE_ARP )
    {
        if ( opcode == ARPOP_REPLY )
        {
            if( arp_add_entry( _net->iface, arp_hdr->src_ip, arp_hdr->src_hw ) < 0 ){
                __die( arpspoof_errbuf );
            }
        }
    }
}

void * arp_receiver( void *conf )
{
    pcap_t *handle;
    int snaplen;
    int timeout;
    int promisc;
    struct net *_net = (struct net *) conf;
    
    snaplen = 64;
    timeout = 50;
    promisc =  0;

    handle = pcap_open_live(
        _net->iface,
        snaplen,
        promisc,
        timeout,
        arpspoof_errbuf
    );

    if ( !handle ) {
        __die( arpspoof_errbuf );
    }

    pcap_loop( handle, -1, packet_handler, (u_char *) conf );
    pcap_close( handle );
    return NULL;
}

// get all live hosts (on the same interface)
short lookup_arp( char *iface, struct endpoint *endps )
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
        sprintf( arpspoof_errbuf, "lookup_arp(): %s", strerror( errno ) );
        return -1;
    }

    live_hosts = 0;
    while ( fgets( line, 0xFF, fp ) )
    {
        sscanf( line, "%s %s %s %s %s %s", addr, hwtype, flags, hwaddr, mask, dev );
        if ( strcmp( iface, dev ) != 0 ) {
            continue;
        }
        memcpy( endps->host_ip,     addr,   strlen( addr )   + 1 );
        memcpy( (endps++)->host_hw, hwaddr, strlen( hwaddr ) + 1 );
        ++live_hosts;
    }
    fseek( fp, 0, SEEK_SET );
    return 0;
}

short endpoint_hw( char *ip, uint8_t *hw, struct endpoint *endps )
{
    if ( live_hosts <= 0 ) {
        return -1;
    }
    for ( register uint32_t i = 0 ; i < live_hosts ; i++ ) {
        if ( strcmp( ip, endps->host_ip ) == 0 ) {
            cnvrt_hw2b( endps->host_hw, hw );
            return 0;
        }
        endps++;
    }
    return -1;
}

// add a new entry to the arp table
// we are adding the entry because we are generating the arp requests
// we are not forcing the kernel to do that
short arp_add_entry( char *iface, uint8_t *ip, uint8_t *hw )
{
    int sock;
    char *ipp;
    struct arpreq req;
    
    if ( (sock = socket( AF_INET, SOCK_STREAM, 0 )) < 0 ) {
        sprintf( 
            arpspoof_errbuf, 
            "%s\n", strerror( errno ) 
        );
        return -1;
    }

    ipp = cnvrt_ipb2str( ip );

    memset( &req, 0, sizeof( req ) );
    strcpy( req.arp_dev, iface );

    req.arp_flags = ATF_COM;

    req.arp_ha.sa_family = AF_UNSPEC;
    memcpy( req.arp_ha.sa_data, hw, 6 );

    struct sockaddr_in *sin = (struct sockaddr_in *) &req.arp_pa;
    sin->sin_family      = AF_INET;
    sin->sin_addr.s_addr = htonl( ip2long( ipp ) );

    if ( ioctl( sock, SIOCSARP, &req ) < 0 ) {
        sprintf(
            arpspoof_errbuf,
            "%s\n", strerror( errno )
        );
        return -1;
    }
    return 0;
}