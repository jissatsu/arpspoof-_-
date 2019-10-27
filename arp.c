#include "arp.h"

void arp_inject( libnet_t *ltag, uint16_t opcode, 
                 uint8_t *src_hw, uint8_t *src_ip,
                 uint8_t *dst_hw, uint8_t *dst_ip ) 
{
    libnet_ptag_t ether, arp;
    char *frmt_src = NULL;
    char *frmt_dst = NULL;

    // arp header
    arp = libnet_build_arp(
        ARPHRD_ETHER,
        ETHERTYPE_IP,
        ETH_ALEN,
        0x04,
        opcode,
        src_hw,
        src_ip,
        dst_hw,
        dst_ip,
        NULL,
        0x00, ltag, 0x00
    );
    if ( arp < 0 ){
        __die( "Arp header error!" );
    }

    // ethernet header
    ether = libnet_build_ethernet( 
        dst_hw,
        src_hw,
        ETHERTYPE_ARP,
        NULL,
        0x00, ltag, 0x00
    );
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

// refresh the arp cache
void arp_refresh( struct net *_net )
{
    int s;
    char *data = "zz";
    char *dst_ip;
    struct sockaddr_in dst;

    if ( (s = socket( AF_INET, SOCK_DGRAM, 0 )) < 0 ) {
        __die( "arp_refresh() - Can't create socket!\n" );
    }

    memset( &dst, 0, sizeof( dst ) );
    dst.sin_family = AF_INET;
    dst.sin_port   = htons( 8080 );
    
    for ( uint32_t i = 1 ; i < _net->hosts_range ; i++ )
    {
        dst_ip = cnvrt_ipb2str( 
            long2ip( _net->start_ip + i )
        );
        
        // skip own address
        if ( strcmp( dst_ip, _net->ip ) == 0 ) {
            continue;
        }
        
        dst.sin_addr.s_addr = inet_addr( dst_ip );
        sendto( 
            s, data, strlen( data ), 0, (struct sockaddr *) &dst, sizeof( dst )
        );
        printf( 
            "\r%s[UDP]%s - destination [ %s ]", GRN, NLL, dst_ip 
        );
        fflush( stdout );
        mssleep( 0.2 );
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

    for ( int8_t i = 0 ; i < 3 ; i++ ) {
        arp_inject(
            lt, ARPOP_REQUEST, src_hw, src_ip, bcast_hw, endpoint_ip
        );
        mssleep( 0.4 );
    }
    printf( "\n" );
}

void packet_handler( u_char *args, const struct pcap_pkthdr *header, 
                     const u_char *packet )
{
    struct net *_net = (struct net *) args;
    struct arpspf_eth_hdr *eth_hdr = (struct arpspf_eth_hdr *) packet;
    struct arpspf_arp_hdr *arp_hdr = (struct arpspf_arp_hdr *) (packet + 14);

    uint16_t eth_type;
    uint16_t opcode;
    uint8_t  dst_hw[6];

    eth_type = ntohs( eth_hdr->eth_type );
    opcode   = ntohs( arp_hdr->opcode );
    cnvrt_hw2b( _net->hw, dst_hw );

    if ( eth_type == ETHERTYPE_ARP && opcode == ARPOP_REPLY )
    {
        // reply is for us?
        if ( arp_hdr->dst_hw[0] == dst_hw[0]
          && arp_hdr->dst_hw[1] == dst_hw[1]
          && arp_hdr->dst_hw[2] == dst_hw[2]
          && arp_hdr->dst_hw[3] == dst_hw[3] )
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
        // ignore incomplete arp
        if ( strcmp( hwaddr, "00:00:00:00:00:00" ) == 0 ) {
            continue;
        }
        memcpy( endps->host_ip,     addr,   strlen( addr )   + 1 );
        memcpy( (endps++)->host_hw, hwaddr, strlen( hwaddr ) + 1 );
        ++live_hosts;
    }
    fseek( fp, 0, SEEK_SET );
    return 0;
}

// add a new entry to the arp table
// we need this function in situations where we are not forcing the kernel to generate the
// arp requests, but instead we are doing it ourselves -> probe_endpoint()
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