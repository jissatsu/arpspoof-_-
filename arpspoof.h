#ifndef __ARPSPOOF_H
#define __ARPSPOOF_H 1

#include "arp.h"

// arpspoof context
struct arpspf_ctx
{
    uint8_t target_ip[4];  // arpspoof target
    uint8_t host_ip[4];    // arpspoof host
};

void arpspoof( char *iface, char *target, char *host );

#endif
