#ifndef __ARPSPOOF_H
#define __ARPSPOOF_H 1

#include <signal.h>
#include "arp.h"

struct spoof_endpoints
{
    char *target;
    uint8_t target_hw[6];
    char *host;
};

short  __init_arpspoof__( char *iface, struct net *_net );
short  arp_receiver_start( struct net *_net );
void   list_targets( struct endpoint *_entps );
void   arpspoof( struct net *_net, struct spoof_endpoints *_spf );
void   __spoof( char *target, uint8_t *t_hw, char *host, struct net *_net );

short match_target( char *target, struct endpoint *_entps );
short endpoint_hw( char *ip, uint8_t *hw, struct endpoint *endps );

#endif
