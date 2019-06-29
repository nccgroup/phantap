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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(X) sizeof((X))/sizeof((X)[0])
#endif

#define EO(mac) (((struct ether_addr *)mac)->ether_addr_octet)
#define ETHER_MULTICAST(mac) (EO(mac)[0] & 0x1)
#define ETHER_ZERO(mac) (!(EO(mac)[0]|EO(mac)[1]|EO(mac)[2]|EO(mac)[3]|EO(mac)[4]|EO(mac)[5]))

unsigned int debug = 0;
#define DEBUG(level, fmt, ...)                   \
    do                                           \
    {                                            \
        if (debug >= level)                      \
        {                                        \
            fprintf(stderr, fmt, ##__VA_ARGS__); \
        }                                        \
    } while (0)

#define ERROR(fmt, ...) DEBUG(0, "Error: "fmt, ##__VA_ARGS__)

#define OPT_ARGS "i:v:"

// Filter Ethernet IPv4 ARP packets (we never know), IPv4 broadcast, and a subset of IPv4 mulitcast (we only want low traffic)
#define BPFFILTER "(arp[0:2] = 0x0001 and arp[2:2] = 0x0800) or (ether broadcast and ether proto \\ip) or (ip dst net 224.0.0.0/8)"

// This allow us to filter route/neigh when displaying / flushing
#define PHANTAP_RTPROTO "255"

pcap_t *pcap_handle = NULL;
char *interface = NULL;

static void usage(void)
{
    fprintf(stderr, "phantap-learn <options>\n");
    fprintf(stderr, "  -i <listen-interface>\tthe interface to listen on\n");
    fprintf(stderr, "  -v <debug-level>\tprint some debug info (level > 0)\n");
    fprintf(stderr, "\nTo show/flush neigh/route\n" \
"ip neigh show proto "PHANTAP_RTPROTO"\n" \
"ip neigh flush nud permanent proto "PHANTAP_RTPROTO"\n" \
"ip route show proto "PHANTAP_RTPROTO"\n" \
"ip route flush proto "PHANTAP_RTPROTO"\n"
);
}

char sbuf[200];
static void add_neighboor(struct ether_addr *mac, struct in_addr *ip)
{
    in_addr_t iph = ntohl(ip->s_addr);
    if (! (IN_MULTICAST(iph) || iph == INADDR_ANY || iph == INADDR_BROADCAST || ETHER_MULTICAST(mac) || ETHER_ZERO(mac))) {
        DEBUG(1, "MAC: %s / IP: %s\n", ether_ntoa(mac), inet_ntoa(*ip));
        snprintf(sbuf, ARRAY_SIZE(sbuf), "ip neigh replace %s dev %s lladdr %s proto "PHANTAP_RTPROTO, inet_ntoa(*ip), interface, ether_ntoa(mac));
        DEBUG(2, "Executing '%s' ...\n", sbuf);
        if (system(sbuf))
            printf("Executing '%s' failed!!\n", sbuf);
        // should we add "scope link" ? "onlink" ?
        snprintf(sbuf, ARRAY_SIZE(sbuf), "ip route replace %s dev %s proto "PHANTAP_RTPROTO, inet_ntoa(*ip), interface);
        DEBUG(2, "Executing '%s' ...\n", sbuf);
        if (system(sbuf))
            printf("Executing '%s' failed!!\n", sbuf);
    }
}

static void handle_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ether_header *eth_header = (struct ether_header *)packet;

    switch (ntohs(eth_header->ether_type))
    {
    case ETHERTYPE_IP:
        if (header->caplen < 34)
        {
            ERROR("IP capture too short %u\n", header->caplen);
            return;
        }
        add_neighboor((struct ether_addr *)eth_header->ether_shost, (struct in_addr *)((uint8_t *) packet + 26));
        // right now ip dest should always broadcast / multicast and be filtered out by the BPF filter
        // but it's cheap to keep it
        add_neighboor((struct ether_addr *)eth_header->ether_dhost, (struct in_addr *)((uint8_t *) packet + 30));
        break;
    case ETHERTYPE_ARP:
        if (header->caplen < 42)
        {
            ERROR("ARP capture too short %u\n", header->caplen);
            return;
        }
        add_neighboor((struct ether_addr *)(packet + 22), (struct in_addr *)(packet + 28));
        add_neighboor((struct ether_addr *)(packet + 32), (struct in_addr *)(packet + 38));
        break;
    default:
        // we should never get there based of the current BPF filter
        printf("Unknown ethertype %hu\n", ntohs(eth_header->ether_type));
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
    struct bpf_program pcapf;

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
    //TODO: check if not too small
    pcap_set_snaplen(pcap_handle, ETH_HLEN+28);

    // We want all the traffic we can get, in particular broadcast/multicast
    pcap_set_promisc(pcap_handle, 1);

    // waking up every 500ms should be enough
    pcap_set_timeout(pcap_handle, 500);

    // Use default for now
    //pcap_set_buffer_size(pcap_handle, );

    if ((pcapstatus = pcap_activate(pcap_handle)) != 0)
    {
        ERROR("pcap_activate issue: %s / %s\n", pcap_statustostr(pcapstatus), pcap_geterr(pcap_handle));
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

    // Compile the BPF filter ...
    if (pcap_compile(pcap_handle, &pcapf, BPFFILTER, 1, PCAP_NETMASK_UNKNOWN) != 0)
    {
        ERROR("pcap_compile error: %s\n", pcap_geterr(pcap_handle));
        goto exit_err;
    }

    // ... and enable it
    if (pcap_setfilter(pcap_handle, &pcapf) != 0)
    {
        ERROR("pcap_setfilter error: %s\n", pcap_geterr(pcap_handle));
        goto exit_err;
    }

    // Loop
    DEBUG(1, "Before loop\n");
    signal(SIGINT, &breakloop);
    if (pcap_loop(pcap_handle, -1, handle_packet, NULL) == -1)
    {
        ERROR("pcap_loop error: %s\n", pcap_geterr(pcap_handle));
        goto exit_err;
    }
    DEBUG(1, "After loop\n");

    status = EXIT_SUCCESS;
exit_err:
    pcap_freecode(&pcapf);

    if (pcap_handle != NULL)
        pcap_close(pcap_handle);

    return status;
}
