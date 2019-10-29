#include "output.h"

void v_ch( char c )
{
    putchar( c );
}

void v_out( vmsg_t type, char *format, ... )
{   
    char *c1, *c2, *pfx;
    char msgf[0xFF];
    va_list list;
    
    c2  = (tty) ? NLL : "" ;
    if ( type == VINF )  c1 = (tty) ? GRN : "", pfx = "[+]";
    if ( type == VWARN ) c1 = (tty) ? YLL : "", pfx = "[*]";
    if ( type == VERR )  c1 = (tty) ? RED : "", pfx = "[!]";
    // no msg type
    if ( type == NVVV )  c1 = "", pfx = "";

    va_start( list, format );
    vsprintf( msgf, format, list );
    printf( "%s%s%s %s", c1, pfx, c2, msgf );
}