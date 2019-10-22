#include "error.h"

void __die( char *msg )
{
    fprintf( stderr, "%s\n", msg );
    exit( 2 );
}