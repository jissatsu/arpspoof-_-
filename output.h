#ifndef __OUTPUT_H
#define __OUTPUT_H 1

#include <unistd.h>
#include "error.h"
#include "color.h"

void v_out( verr_t err, char *msg );
void v_ch( char c );

#endif