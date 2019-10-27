#ifndef __ARPSPOOF_H
#define __ARPSPOOF_H 1

#include <signal.h>
#include "arp.h"

struct spf_endpoints
{
    char target[25];
    uint8_t target_hw[6];
    char gateway[25];
    uint8_t gateway_hw[6];
}
endpoints;

short  __init_arpspoof__( char *iface, struct net *_net );
short  arp_receiver_start( struct net *_net );
void   list_targets( struct endpoint *_entps );
void   arpspoof( struct net *_net, struct spf_endpoints *_spf );
void   __spoof( struct spf_endpoints *_spf, struct net *_net );
void   arp_clear_arp( struct spf_endpoints *_spf );
void   gather_endpoints( struct spf_endpoints *_spf, short target );

short match_target( char *target, struct endpoint *_entps );
short endpoint_hw( char *ip, uint8_t *hw, struct endpoint *endps );

#endif
