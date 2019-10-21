#ifndef __ADDR_H
#define __ADDR_H 1

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif

void cnvrt_ip2b( char *ip, uint8_t *dst );
void cnvrt_hw2b( char *hw, uint8_t *dst );
short dev_addr( char *iface, uint8_t *dst, char *errbuf );

#ifdef __cplusplus
}
#endif

#endif