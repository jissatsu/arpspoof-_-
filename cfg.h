#ifndef __CFG_H
#define __CFG_H 1

struct endpoint
{
    char host_ip[25];
    char host_hw[25];
    uint8_t bhost_ip[4];
    uint8_t bhost_hw[6];
}
_endps[65534];

struct spf_endpoints
{
    char target[25];
    char target_hw[25];
    char gateway[25];
    char gateway_hw[25];
}
endpoints;

#endif