#ifndef __ERROR_H
#define __ERROR_H 1

#include <stdio.h>
#include <stdlib.h>

char arpspoof_errbuf[0xFF];

void __die( char *msg );

typedef enum { NVVV, VERR, VINF, VWARN } vmsg_t;

#endif