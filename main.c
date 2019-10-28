#include "arpspoof.h"

void _usage( char *prog )
{
    fprintf( stdout, "Usage: %s", prog );
    fprintf( stdout, "-i [INTERFACE NAME]" );
    fprintf( stdout, "-t [TARGET IP]" );
    fprintf( stdout, "-m [TARGET MAC" );
    fprintf( stdout, "-g [GATEWAY IP]" );
    exit( 2 );
}

int main( int argc, char **argv )
{
    char *gateway;
    char *target;
    char *iface;
    int opt;
    struct net _net;

    gateway = NULL;
    target  = NULL;
    iface   = NULL;

    while ( (opt = getopt( argc, argv, "t:g:i:m:" )) != -1 )
    {
        switch ( opt ) {
            case 'i': iface   = optarg; break; 
            case 't': target  = optarg; break;
            case 'g': gateway = optarg; break;
            default:
                _usage( argv[0] );
        }
    }

    if ( !iface || !gateway ) {
        _usage( argv[0] );
    }

    if( __init_arpspoof__( iface, &_net ) < 0 )
        __die( arpspoof_errbuf );

    v_out( VINF, "Arpspoof initialized!\n" );

    if ( !target ) {
        strcpy( endpoints.target, "0" );
    } else {
        strcpy( endpoints.target, target );
    }
    
    strcpy( endpoints.gateway, gateway );
    arpspoof( &_net, &endpoints );
    exit( 0 );
}