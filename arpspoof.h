#ifndef __ARPSPOOF_H
#define __ARPSPOOF_H 1

#include "arp.h"

struct spoof_endpoints
{
    char *target;
    char *host;
};

void arpspoof( struct net *_net, struct spoof_endpoints *_spf );

#endif
