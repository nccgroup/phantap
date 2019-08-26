/*
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
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "common.h"
unsigned int debug = 0;

#define OPT_ARGS "i:v:"

// Filter ethernet/IPv4 broadcast, a subset of IPv4 mulitcast (we only want local & low traffic multicast),
// and ethernet IPv4 ARP packets (we never know). Exclude tagged traffic as libpcap/linux include it by default
#define BPFFILTER "\
(\
       (ether proto 0x0800 and ether broadcast) \
    or (ip dst 0.0.0.0) \
    or (ip dst 255.255.255.255) \
    or (ip dst net 224.0.0.0/24) \
    or (ip dst net 239.255.255.0/24) \
    or (arp[0:2] = 0x0001 and arp[2:2] = 0x0800) \
) and not vlan"

pcap_t *pcap_handle = NULL;
char *interface = NULL;

static void usage(void)
{
    fprintf(stderr, "phantap-learn <options>\n");
    fprintf(stderr, "  -i <listen-interface>\tthe interface to listen on\n");
    fprintf(stderr, "  -v <debug-level>\tprint some debug info (level > 0)\n");
    fprintf(stderr, "\nTo show/flush neigh/route\n"
                    "ip neigh show nud permanent\n"
                    "ip neigh flush nud permanent\n"
                    "ip route show proto " PHANTAP_RTPROTO "\n"
                    "ip route flush proto " PHANTAP_RTPROTO "\n");
}

static void handle_neighboor(const struct ether_addr *mac, const struct in_addr *ip, bool arp)
{
    if (!IN_ADDR_NORMAL(*ip) || !ETHER_ADDR_NORMAL(mac))
    {
        // we don't want to add multicast / broadcast to the neigboor
        return;
    }

    char sbuf[200];
    DEBUG(2, "MAC: %s / IP: %s\n", ether_ntoa(mac), inet_ntoa(*ip));
    snprintf(sbuf, ARRAY_SIZE(sbuf),
             "ip neigh replace %s dev %s lladdr %s", inet_ntoa(*ip), interface, ether_ntoa(mac));
    DEBUG(3, "Executing '%s' ...\n", sbuf);
    if (system(sbuf))
        ERROR("Executing '%s' failed!!\n", sbuf);
    // should we add "scope link" ? "onlink" ?
    snprintf(sbuf, ARRAY_SIZE(sbuf),
             "ip route replace %s dev %s proto " PHANTAP_RTPROTO,
             inet_ntoa(*ip), interface);
    DEBUG(3, "Executing '%s' ...\n", sbuf);
    if (system(sbuf))
        ERROR("Executing '%s' failed!!\n", sbuf);
}

static bool set_bpf_filter(const char *filter)
{
    struct bpf_program pcapf;
    bool ret = false;

    // Compile the BPF filter ...
    if (pcap_compile(pcap_handle, &pcapf, filter, 1, PCAP_NETMASK_UNKNOWN) != 0)
    {
        ERROR("pcap_compile error: %s\n", pcap_geterr(pcap_handle));
        goto set_filter_exit_err;
    }

    // ... and enable it
    if (pcap_setfilter(pcap_handle, &pcapf) != 0)
    {
        ERROR("pcap_setfilter error: %s\n", pcap_geterr(pcap_handle));
        goto set_filter_exit_err;
    }

    ret = true;

set_filter_exit_err:
    pcap_freecode(&pcapf);
    return ret;
}

static void handle_packet(u_char *args, const struct pcap_pkthdr *pkt_hdr, const u_char *packet)
{
    uint32_t caplen = pkt_hdr->caplen;
    if (caplen < sizeof(struct ether_header))
    {
        ERROR("Capture too short for Ethernet (%u)\n", caplen);
        return;
    }
    const struct ether_header *eth_hdr = (struct ether_header *)packet;

    switch (ntohs(eth_hdr->ether_type))
    {
    case ETHERTYPE_IP:
        if (caplen < sizeof(struct ether_header) + sizeof(struct ip))
        {
            ERROR("Capture too short for IP (%u)\n", caplen);
            return;
        }
        const struct ip *ip_hdr = (struct ip *)(eth_hdr + 1);
        handle_neighboor((struct ether_addr *)eth_hdr->ether_shost, &ip_hdr->ip_src, false);
        // right now ip_dst should always be broadcast / multicast and be filtered
        // out by the BPF filter, but it's cheap to keep it
        handle_neighboor((struct ether_addr *)eth_hdr->ether_dhost, &ip_hdr->ip_dst, false);
        break;
    case ETHERTYPE_ARP:
        if (caplen < sizeof(struct ether_header) + sizeof(struct ether_arp))
        {
            ERROR("Capture too short for ARP (%u)\n", caplen);
            return;
        }
        const struct ether_arp *arp = (struct ether_arp *)(eth_hdr + 1);
        if (!(ntohs(arp->arp_hrd) == ARPHRD_ETHER && ntohs(arp->arp_pro) == ETHERTYPE_IP &&
              arp->arp_hln == ETH_ALEN && arp->arp_pln == sizeof(struct in_addr)))
        {
            ERROR("ARP packet is wrong (%#06x,%#06x,%#04x,%#04x)\n",
                  ntohs(arp->arp_hrd), ntohs(arp->arp_pro), arp->arp_hln, arp->arp_pln);
            return;
        }
        handle_neighboor((struct ether_addr *)(arp->arp_sha), (struct in_addr *)(arp->arp_spa), true);
        handle_neighboor((struct ether_addr *)(arp->arp_tha), (struct in_addr *)(arp->arp_tpa), true);
        break;
    default:
        // we should never get there based of the current BPF filter
        ERROR("Unknown ethertype %#06x\n", ntohs(eth_hdr->ether_type));
    }
}

static void breakloop(int signum)
{
    pcap_breakloop(pcap_handle);
}

int main(int argc, char **argv)
{
    int ch, pcapstatus, datalink;
    int status = EXIT_FAILURE;
    char errbuf[PCAP_ERRBUF_SIZE];

    while ((ch = getopt(argc, argv, OPT_ARGS)) != -1)
    {
        switch (ch)
        {
        case 'i':
            interface = optarg;
            break;
        case 'v':
            debug = atoi(optarg);
            break;
        }
    }

    if (interface == NULL)
    {
        ERROR("interface (-i) is mandatory !!!\n\n");
        usage();
        goto exit_err;
    }

    if ((pcap_handle = pcap_create(interface, errbuf)) == NULL)
    {
        ERROR("pcap_create failed: %s\n\n", errbuf);
        goto exit_err;
    }

    // Ethernet header (14) + ARP IPv4 (28) == 42
    // Ethernet header (14) + IPv4 header (20) == 34
    pcap_set_snaplen(pcap_handle, ETH_HLEN + sizeof(struct ether_arp));

    // We want all the traffic we can get, in particular broadcast/multicast
    pcap_set_promisc(pcap_handle, 1);

    // waking up every 500ms should be enough
    pcap_set_timeout(pcap_handle, 500);

    // Use default for now
    //pcap_set_buffer_size(pcap_handle, );

    if ((pcapstatus = pcap_activate(pcap_handle)) != 0)
    {
        ERROR("pcap_activate issue: %s / %s\n",
              pcap_statustostr(pcapstatus), pcap_geterr(pcap_handle));
        goto exit_err;
    }

    // Check that current interface datalink is DLT_EN10MB (Ethernet)
    if ((datalink = pcap_datalink(pcap_handle)) != DLT_EN10MB)
    {
        ERROR("we only support DLT_EN10MB datalink, current datalink %d\n", datalink);
        goto exit_err;
    }

    // Ingress traffic is enough
    if (pcap_setdirection(pcap_handle, PCAP_D_IN) != 0)
    {
        ERROR("pcap_setdirection error: %s\n", pcap_geterr(pcap_handle));
        goto exit_err;
    }

    if (set_bpf_filter(BPFFILTER) == false)
        goto exit_err;

    // Loop
    DEBUG(2, "Before pcap_loop\n");
    signal(SIGINT, &breakloop);
    if (pcap_loop(pcap_handle, -1, handle_packet, NULL) == -1)
    {
        ERROR("pcap_loop error: %s\n", pcap_geterr(pcap_handle));
        goto exit_err;
    }
    DEBUG(2, "After pcap_loop\n");

    status = EXIT_SUCCESS;
exit_err:
    if (pcap_handle != NULL)
        pcap_close(pcap_handle);

    return status;
}
