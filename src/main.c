#include "arpspoof.h"

void _usage( char *prog )
{
    fprintf( stdout, "Usage: %s [OPTIONS]\n", prog );
    fprintf( stdout, "-h [SHOW HELP]\n" );
    fprintf( stdout, "-i [INTERFACE NAME]\n" );
    fprintf( stdout, "-t [TARGET IP]\n" );
    fprintf( stdout, "-m [TARGET MAC\n" );
    fprintf( stdout, "-g [GATEWAY IP]\n" );
    exit( 2 );
}

int main( int argc, char **argv )
{
    char *gateway;
    char *target;
    char *iface;
    int opt;

    gateway = NULL;
    target  = NULL;
    iface   = NULL;

    while ( (opt = getopt( argc, argv, "t:g:i:m:h" )) != -1 )
    {
        switch ( opt ) {
            case 'i': iface   = optarg; break;
            case 't': target  = optarg; break;
            case 'g': gateway = optarg; break;
			case 'h': _usage( argv[0] );
            default:
                _usage( argv[0] );
        }
    }

    if ( !iface || !gateway ) {
        _usage( argv[0] );
    }

    if( __arpspoof_setup__( iface, &_net ) < 0 )
        __die( arpspoof_errbuf );

    v_out( VINF, "%s", "Arpspoof initialized!\n" );

    strcpy( endpoints.target, (!target) ? "0" : target );
    strcpy( endpoints.gateway, gateway );

    arpspoof( &_net, &endpoints );
    exit( 0 );
}
