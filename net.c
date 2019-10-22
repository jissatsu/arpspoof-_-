#include "net.h"


uint32_t ip2long( char *ip )
{
    uint8_t cnvrt[4];
    uint32_t _long = 0;

    cnvrt_ip2b( ip, cnvrt );
    _long += (uint32_t) (cnvrt[0] << 24);
    _long += (uint32_t) (cnvrt[1] << 16);
    _long += (uint32_t) (cnvrt[2] << 8);
    _long += (uint32_t) (cnvrt[3] << 0);
    return _long;
}

// calculate the host range of the network
uint32_t calc_hosts( char *ip, char *nmask )
{
    uint32_t lip, lmask;
    uint32_t nhosts = 0;

    lip    = ip2long( ip );
    lmask  = ip2long( nmask );
    nhosts = lmask ^ 0xFFFFFFFF;
    return nhosts;
}

// calculate network start ip
uint32_t net_off( char *ip, char *nmask )
{
    uint32_t lip, lmask;
    uint32_t off = 0;

    lip   = ip2long( ip );
    lmask = ip2long( nmask );
    off   = lip & lmask;
    return off;
}

// initialize the network
void init_net( char *iface, struct net *_net )
{
    if ( dev_addr( iface, _net->ip, IPV4, arpspoof_errbuf ) < 0 ) {
        __die( arpspoof_errbuf );
    }
    if ( dev_addr( iface, _net->nmask, MASK, arpspoof_errbuf ) < 0 ) {
        __die( arpspoof_errbuf );
    }
    
    _net->iface = iface;
    _net->hosts_range = calc_hosts( _net->ip, _net->nmask );
    _net->start_ip    = net_off(    _net->ip, _net->nmask );
}

short cnvrt_ip2b( char *ip, uint8_t *dst )
{
    register int i, j;
    char frag[4];
    uint8_t dst_ip[4];

    if ( is_ipv4_format( ip ) < 0 ) {
        return -1;
    }

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
    return 0;
}

short cnvrt_hw2b( char *hw, uint8_t *dst )
{
    int scan;
    unsigned int _zhw[6];
    unsigned char _hw[6];
    
    scan = sscanf( 
        hw, "%x:%x:%x:%x:%x:%x", 
        &_zhw[0], &_zhw[1], &_zhw[2], &_zhw[3], &_zhw[4], &_zhw[5]
    );

    if ( scan != EOF ) {
        for ( register int i = 0 ; i < 6 ; i++ ) {
            _hw[i] = (unsigned char) _zhw[i];
        }
        memcpy( dst, _hw, 6 );
        return 0;
    }
    return -1;
}


/* check if the hardware address has a valid format -> x:x:x:x:x:x */
short is_hw_format( char *hw )
{
    int scan = 0;
    unsigned int _zhw[6];

    sscanf( 
        hw, "%x:%x:%x:%x:%x:%x", 
        &_zhw[0], &_zhw[1], &_zhw[2], &_zhw[3], &_zhw[4], &_zhw[5]
    );
    return ( scan != EOF ) ? 0 : -1 ;
}


/* check if ip address has valid format -> d.d.d.d */
short is_ipv4_format( char *ip )
{
    int scan = 0;
    unsigned int _zip[4];
    
    sscanf(
        ip, "%d.%d.%d.%d", &_zip[0], &_zip[1], &_zip[2], &_zip[3]
    );
    return ( scan != EOF ) ? 0 : -1 ;
}


/* get ip address or netmask of device */
short dev_addr( char *iface, char *dst, addr_num_t type,
                char *errbuf )
{
    int sockfd;
    char *ipaddr;
    unsigned long flag;
    struct sockaddr_in *addr;
    struct ifreq req;

    if ( (sockfd = socket( AF_INET, SOCK_STREAM, 0 )) < 0 ) {
        sprintf( errbuf, "%s", strerror( errno ) );
        return -1;
    }

    if ( type == IPV4 )
        flag = SIOCGIFADDR;
    
    if ( type == MASK )
        flag = SIOCGIFNETMASK;

    strcpy( req.ifr_name, iface );
    if ( ioctl( sockfd, flag, &req ) < 0 ) {
        sprintf( errbuf, "%s", strerror( errno ) );
        return -1;
    }

    addr   = (struct sockaddr_in *) &req.ifr_addr;
    ipaddr = inet_ntoa( addr->sin_addr );
    memcpy( dst, ipaddr, strlen( ipaddr ) + 1 );
    return 0;
}