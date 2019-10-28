#ifndef __ARPSPOOF_H
#define __ARPSPOOF_H 1

#include <signal.h>
#include "arp.h"

struct spf_endpoints
{
    char target[25];
    char target_hw[25];
    char gateway[25];
    char gateway_hw[25];
}
endpoints;

short  __init_arpspoof__( char *iface, struct net *_net );
short  arp_receiver_start( struct net *_net );
void   arpspoof( struct net *_net, struct spf_endpoints *_spf );
void   __spoof( struct spf_endpoints *_spf, struct net *_net );
void   arp_clear_arp( struct spf_endpoints *_spf );
void   set_endpoints( char *iface, struct spf_endpoints *_spf );

#endif
