#ifndef __ARPSPOOF_H
#define __ARPSPOOF_H 1

#include "arp.h"

struct spoof_endpoints
{
    char *target;
    char *host;
};

void arpspoof( char *iface, char *target, char *host );

#endif
