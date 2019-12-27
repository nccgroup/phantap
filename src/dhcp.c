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

#define _GNU_SOURCE
#include <pcap/pcap.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

#include "common.h"
#include "dhcp.h"
#include "phantap-learn.h"

void handle_dhcp(const struct dhcp_packet *dhcp_pkt, const uint8_t *end)
{
    DEBUG(3, "Start handle_dhcp\n");
    const uint8_t *cur = (uint8_t *)(dhcp_pkt + 1);
    if (cur >= end)
    {
        ERROR("Capture too short for DHCP4\n");
        return;
    }
    if (dhcp_pkt->op != BOOTREPLY)
    {
        DEBUG(2, "Ignoring non reply DHCP4 packet (%u)\n", dhcp_pkt->op);
        return;
    }
    if (!(dhcp_pkt->htype == ARPHRD_ETHER && dhcp_pkt->hlen == ETH_ALEN &&
          ntohl(dhcp_pkt->cookie) == DHCP_COOKIE))
    {
        ERROR("Invalid DHCP4 packet\n");
        return;
    }

    struct netinfo ni = {};
    ni.dhcp4 = ni.changed = true;
    while (cur < end)
    {
        uint8_t option = *cur;
        cur++;
        if (option == OPTION_PAD || option == OPTION_END)
            break;

        if (cur >= end)
        {
            ERROR("Trying to read after the end of the dhcp4 packet\n");
            break;
        }
        uint8_t len = *cur;
        cur++;
        if (cur + len > end)
        {
            ERROR("Option ends after capture end\n");
            break;
        }

        switch (option)
        {
        case OPTION_MESSAGE_TYPE:
        case OPTION_IP_TTL:
            if (len != 1)
            {
                ERROR("DHCP4 option %u, len should be 1 but is %u\n", option, len);
            }
            break;

        case OPTION_SERVER_IDENTIFIER:
        case OPTION_LEASE_TIME:
        case OPTION_NETMASK:
        case OPTION_TIME_OFFSET:
            if (len != 4)
            {
                ERROR("DHCP4 option %u, len should be 4 but is %u\n", option, len);
            }
            break;

        case OPTION_ROUTER:
        case OPTION_DNSSERVER:
        case OPTION_NTPSERVER:
            if (len % 4 != 0)
            {
                ERROR("DHCP4 option %u, len should be a multiple of 4 but is %u\n", option, len);
            }
            break;

        case OPTION_HOSTNAME:
        case OPTION_DOMAINNAME:
            // variable length
        default:
            break;
        }

        switch (option)
        {
        case OPTION_MESSAGE_TYPE:
            DEBUG(2, "DHCP4 message type %u\n", *cur);
            switch (*cur)
            {
            case DHCPDECLINE:
            case DHCPNAK:
            case DHCPRELEASE:
                // We might have a bad config, blocking traffic
                block_traffic();
                goto dhcp_while_end;
            case DHCPDISCOVER:
            case DHCPOFFER:
            case DHCPREQUEST:
            case DHCPINFORM:
                // These packets are not interesting, ignoring
                goto dhcp_while_end;
            case DHCPACK:
                // We should have all our info in this packet, so continue
                break;
            default:
                ERROR("DHCP4 Message Type impossible value %u\n", *cur);
                goto dhcp_while_end;
            }
            break;
        case OPTION_NETMASK:
            ni.victim_ip4 = dhcp_pkt->yiaddr;
            ni.victim_netmask4 = *(struct in_addr *)cur;
            break;
        case OPTION_ROUTER:
            ni.gateway_ip4 = *(struct in_addr *)cur;
            break;
        case OPTION_DNSSERVER:
            ni.dns4 = *(struct in_addr *)cur;
            break;
        case OPTION_NTPSERVER:
            ni.ntp4 = *(struct in_addr *)cur;
            break;
        default:
            break;
        }

        cur += len;
    }

    if (IN_ADDR_EQ(cur_ni.victim_ip4, ni.victim_ip4) &&
        IN_ADDR_EQ(cur_ni.victim_netmask4, ni.victim_netmask4) &&
        IN_ADDR_EQ(cur_ni.gateway_ip4, ni.gateway_ip4) &&
        IN_ADDR_EQ(cur_ni.dns4, ni.dns4))
    {
        DEBUG(1, "No DHCP4 config changes\n");
    }
    else
    {
        memcpy(&cur_ni, &ni, sizeof(cur_ni));
        DEBUG(1, "New DHCP4 config detected: ");
        DEBUG(1, "IP4=%s ", inet_ntoa(cur_ni.victim_ip4));
        DEBUG(1, "NETMASK4=%s ", inet_ntoa(cur_ni.victim_netmask4));
        DEBUG(1, "GATEWAY4=%s ", inet_ntoa(cur_ni.gateway_ip4));
        DEBUG(1, "DNS4=%s ", inet_ntoa(cur_ni.dns4));
        DEBUG(1, "NTP4=%s\n", inet_ntoa(cur_ni.ntp4));
        // we have new config but we don't have the gateway_mac yet, so block traffic
        block_traffic();
    }

dhcp_while_end:
    DEBUG(3, "End handle_dhcp\n");
}
