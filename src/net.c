#include "net.h"

// convert an ip address from dotted string to long
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

// convert an ip address from long to 4 byte array
uint8_t * long2ip( uint32_t _long )
{
    static uint8_t ip[4];
    ip[0] = (_long >> 24) & 0xFF;
    ip[1] = (_long >> 16) & 0xFF;
    ip[2] = (_long >>  8) & 0xFF;
    ip[3] = (_long >>  0) & 0xFF;
    return ip;
}

// calculate the range of the network
uint32_t calc_hosts( char *ip, char *nmask )
{
    uint32_t lmask;
    uint32_t nhosts = 0;

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

// calculate the subnet /16, /17, /24, etc...
short calc_subnet( char *nmask )
{
    short subnet;
    uint32_t lmask;

    subnet = 0;
    lmask  = ip2long( nmask );
    
    do {
        if ( lmask & 01 ) {
            subnet++;
        }
    } while( lmask >>= 1 );
    return subnet;
}

// convert an ip address from a dotted string to 4 byte array
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

// convert an ip address from 4 byte array to a dotted string representation
char * cnvrt_ipb2str( uint8_t *ip )
{
    char *_ip = (char *) malloc( 25 );
    sprintf( _ip, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3] );
    return _ip;
}

// convert a hardware address from a colon separated string to 6 byte array
short cnvrt_hw2b( char *hw, uint8_t *dst )
{
    int scan;
    unsigned int _zhw[6];
    unsigned char _hw[6];
    
    scan = sscanf( 
        hw, "%x:%x:%x:%x:%x:%x", 
        &_zhw[0], &_zhw[1], &_zhw[2], &_zhw[3], &_zhw[4], &_zhw[5]
    );

    if ( scan == EOF ) {
        return -1;
    }
    for ( register int i = 0 ; i < 6 ; i++ ) {
        _hw[i] = (unsigned char) _zhw[i];
    }
    memcpy( dst, _hw, 6 );
    return 0;
}

/* check if ip address has valid format -> d.d.d.d */
short is_ipv4_format( char *ip )
{
    int scan = 0;
    unsigned int _zip[4];
    
    sscanf(
        ip, "%d.%d.%d.%d", &_zip[0], &_zip[1], &_zip[2], &_zip[3]
    );
    if ( scan == EOF ) {
        return -1;
    }
    for ( int i = 0 ; i < 4 ; i++ ) {
        if ( _zip[i] < 0 || _zip[i] > 255 ) {
            return -1;
        }
    }
    return 0;
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
