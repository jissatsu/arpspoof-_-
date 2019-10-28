#include "output.h"

void v_out( verr_t err, char *msg )
{
    int tty;
    char *c1, *c2, *pfx;
    char msgf[0xFF];

    tty = isatty( 1 );
    c2  = (tty) ? NLL : "" ;

    if ( err == VINF )  c1 = (tty) ? GRN : "", pfx = "[+]";
    if ( err == VWARN ) c1 = (tty) ? YLL : "", pfx = "[*]";
    if ( err == VERR )  c1 = (tty) ? RED : "", pfx = "[!]";

    sprintf( msgf, "%s%s%s %s", c1, pfx, c2, msg );
    printf( "%s", msgf );
}

// print a single character
void v_ch( char c )
{
    printf( "%c", c );
}