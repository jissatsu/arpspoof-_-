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
    char *host;
    char *target;
    char *iface;
    int opt;
    struct arpspf_ctx arpsf;
    char errbuf[0xFF];

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

    if ( !iface || !host || !target ) {
        _usage( argv[0] );
    }

    arpsf.iface  = iface;
    arpsf.host   = host;
    arpsf.target = target;

    if( killua::arpspoof( &arpsf, errbuf ) < 0 )
    {
        std::cerr << errbuf << std::endl;
    }
    return 0;
}