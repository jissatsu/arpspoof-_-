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

uint32_t nhosts( char *netmask )
{
    uint32_t nhosts = 0;
    return nhosts;
}


short arp_refresh( void )
{
    int s;
    if ( (s = socket( AF_INET, SOCK_DGRAM, 0 )) < 0 ) {
        return -1;
    }
}


void cnvrt_ip2b( char *ip, uint8_t *dst )
{
    register int i, j;
    char frag[4];
    uint8_t dst_ip[4];

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
}


void cnvrt_hw2b( char *hw, uint8_t *dst )
{
    unsigned int _zhw[6];
    unsigned char _hw[6];
    sscanf( 
        hw, "%x:%x:%x:%x:%x:%x", 
        &_zhw[0], &_zhw[1], &_zhw[2], &_zhw[3], &_zhw[4], &_zhw[5]
    );

    for ( register int i = 0 ; i < 6 ; i++ ) {
        _hw[i] = (unsigned char) _zhw[i];
    }
    memcpy( dst, _hw, 6 );
}


/* check if the hardware address has a valid format -> x:x:x:x:x:x */
short is_hw_format( char *hw )
{
    int scan;
    unsigned int _zhw[6];

    sscanf( 
        hw, "%x:%x:%x:%x:%x:%x", 
        &_zhw[0], &_zhw[1], &_zhw[2], &_zhw[3], &_zhw[4], &_zhw[5]
    );
    return ( scan != EOF ) ? 0 : -1 ;
}


/* chack if ip address has valid format -> d.d.d.d */
short is_ipv4_format( char *ip )
{
    int scan;
    unsigned int _zip[4];
    
    sscanf(
        ip, "%d.%d.%d.%d", &_zip[0], &_zip[1], &_zip[2], &_zip[3]
    );
    return ( scan != EOF ) ? 0 : -1 ;
}


/* get ip address of interface */
short dev_addr( char *iface, uint8_t *dst, char *errbuf )
{
    int sockfd;
    struct sockaddr_in *addr;
    struct ifreq req;

    if ( (sockfd = socket( AF_INET, SOCK_STREAM, 0 )) < 0 ) {
        sprintf( errbuf, "%s", strerror( errno ) );
        return -1;
    }

    strcpy( req.ifr_name, iface );
    if ( ioctl( sockfd, SIOCGIFADDR, &req ) < 0 ) {
        sprintf( errbuf, "%s", strerror( errno ) );
        return -1;
    }

    addr = (struct sockaddr_in *) &req.ifr_addr;
    cnvrt_ip2b( inet_ntoa( addr->sin_addr ), dst );
    return 0;
}