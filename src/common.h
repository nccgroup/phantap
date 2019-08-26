/*
 * Copyright (C) 2019 Diana Dragusin <diana.dragusin@nccgroup.com>
 * Copyright (C) 2019 Etienne Champetier <champetier.etienne@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef __COMMON_H
#define __COMMON_H

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(X) sizeof((X)) / sizeof((X)[0])
#endif

#define EO(mac) (((struct ether_addr *)mac)->ether_addr_octet)
#define ETHER_MULTICAST(mac) (EO(mac)[0] & 0x1)
#define ETHER_ZERO(mac) (!(EO(mac)[0] | EO(mac)[1] | EO(mac)[2] | EO(mac)[3] | EO(mac)[4] | EO(mac)[5]))
#define ETHER_ADDR_NORMAL(mac) (!ETHER_MULTICAST(mac) && !ETHER_ZERO(mac))
#define ETHER_CMP(maca, macb) memcmp(maca, macb, sizeof(struct ether_addr))
#define ETHER_CPY(maca, macb) memcpy(maca, macb, sizeof(struct ether_addr))

#define IN_ADDR_NORMAL(ip) (ntohl((ip).s_addr) != INADDR_ANY && \
                            (IN_CLASSA(ntohl((ip).s_addr)) ||   \
                             IN_CLASSB(ntohl((ip).s_addr)) ||   \
                             IN_CLASSC(ntohl((ip).s_addr))))
#define IN_ADDR_EQ(ipa, ipb) (ipa.s_addr == ipb.s_addr)
#define IN_SAME_NET(ipa, ipb, net) ((ntohl(ipa.s_addr) & net) == (ntohl(ipb.s_addr) & net))

extern unsigned int debug;
#define DEBUG(level, fmt, ...)                   \
    do                                           \
    {                                            \
        if (debug >= level)                      \
        {                                        \
            fprintf(stderr, fmt, ##__VA_ARGS__); \
        }                                        \
    } while (0)

#define ERROR(fmt, ...) DEBUG(0, "Error: " fmt, ##__VA_ARGS__)

// This allow us to filter route/neigh when displaying / flushing
#define PHANTAP_RTPROTO "255"

#include <stdbool.h>
#include <net/ethernet.h>
#include <netinet/in.h>
struct netinfo
{
    struct ether_addr victim_mac, gateway_mac;
    struct in_addr victim_ip, victim_netmask, gateway_ip, dns, ntp;
    bool dhcp, changed;
};

extern struct netinfo cur_ni;

#endif
