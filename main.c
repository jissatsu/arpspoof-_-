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
    uint8_t ipp[4];

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

    init_net( iface, &_net );
    return 0;
}