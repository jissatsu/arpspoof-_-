#include "addr.h"

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