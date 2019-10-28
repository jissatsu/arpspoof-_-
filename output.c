#include "output.h"

void v_out( verr_t err, char *msg )
{
    char *color;
    char *pfx;

    if ( err == VINF )  color = GRN, pfx = "[+]";
    if ( err == VWARN ) color = YLL, pfx = "[*]";
    if ( err == VERR )  color = RED, pfx = "[!]";

    printf( "%s%s%s %s\n", color, pfx, NLL, msg );
}