#include "arpspoof.h"

void _usage( char *prog )
{
    fprintf( stdout, "Usage: %s", prog );
    fprintf( stdout, "-i [INTERFACE NAME]" );
    fprintf( stdout, "-t [TARGET IP]" );
    fprintf( stdout, "-m [TARGET MAC" );
    fprintf( stdout, "-h [HOST IP]" );
    exit( 2 );
}

int main( int argc, char **argv )
{
    char *host;
    char *target;
    char *iface;
    int opt;
    struct net _net;
    struct spoof_endpoints _spf;

    host   = NULL;
    target = NULL;
    iface  = NULL;

    while ( (opt = getopt( argc, argv, "t:h:i:m:" )) != -1 )
    {
        switch ( opt ) {
            case 'i': iface  = optarg; break; 
            case 't': target = optarg; break;
            case 'h': host   = optarg; break;
            default:
                _usage( argv[0] );
        }
    }

    if ( !iface || !host ) {
        _usage( argv[0] );
    }

    if( __init_arpspoof__( iface, &_net ) < 0 ) {
        __die( arpspoof_errbuf );
    }

    printf( "%s[+]%s Arpspoof initialized!\n", GRN, NLL );

    _spf.target = target;
    _spf.host   = host;
    
    arpspoof( &_net, &_spf );
    exit( 0 );
}