#include "arpspoof.hpp"

void _usage( char *prog )
{
    std::cout << "Usage: " << prog     << std::endl;
    std::cout << "-i [INTERFACE NAME]" << std::endl;
    std::cout << "-t [TARGET IP]"      << std::endl;
    std::cout << "-m [TARGET MAC"      << std::endl;
    std::cout << "-h [HOST IP]"        << std::endl;
    exit( 2 );
}

int main( int argc, char **argv )
{
    struct arpsf_ctx ctx;
    char *host;
    char *target;
    char *target_hw;
    char *iface;
    int opt;

    host      = NULL;
    target    = NULL;
    target_hw = NULL;
    iface     = NULL;

    while ( (opt = getopt( argc, argv, "t:h:i:m:" )) != -1 )
    {
        switch ( opt ) {
            case 'i': iface     = optarg; break; 
            case 't': target    = optarg; break;
            case 'm': target_hw = optarg; break;
            case 'h': host      = optarg; break;
            default:
                _usage( argv[0] );
        }
    }

    if ( !host || !target || !target_hw ) {
        _usage( argv[0] );
    }

    killua::cnvrt_ip2b( target, (&ctx)->target );
    killua::cnvrt_ip2b( host, (&ctx)->host );
    killua::arpspoof( &ctx, iface );
    return 0;
}