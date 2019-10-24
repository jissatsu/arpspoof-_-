#ifndef __ARPSPOOF_H
#define __ARPSPOOF_H 1

#include <signal.h>
#include "arp.h"

struct spoof_endpoints
{
    char *target;
    char *host;
};

short  __init_arpspoof__( char *iface, struct net *_net );
short  arp_receiver_start( struct net *_net );
void   list_targets( struct endpoint *_entps );
void   arpspoof( struct net *_net, struct spoof_endpoints *_spf );

#endif
