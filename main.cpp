#include "arpspoof.hpp"

void _usage( char *prog )
{
    std::cout << "Usage: " << prog     << std::endl;
    std::cout << "-i [INTERFACE NAME]" << std::endl;
    std::cout << "-t [TARGET IP]"      << std::endl;
    std::cout << "-h [HOST IP]"        << std::endl;
    exit( 2 );
}

int main( int argc, char **argv )
{
    struct arpsf_ctx ctx;
    char *host;
    char *target;
    char *iface;
    int opt;

    host   = NULL;
    target = NULL;
    iface  = NULL;

    while ( (opt = getopt( argc, argv, "t:h:i:" )) != -1 )
    {
        switch ( opt ) {
            case 'i': iface  = optarg; break; 
            case 't': target = optarg; break;
            case 'h': host   = optarg; break;
            default:
                _usage( argv[0] );
        }
    }

    if ( !host || !target ) {
        _usage( argv[0] );
    }

    cnvrt_ip2b( target, (&ctx)->target );
    cnvrt_ip2b( host, (&ctx)->host );
    arpspoof( &ctx, iface );
    return 0;
}