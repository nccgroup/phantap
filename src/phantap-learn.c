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
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "common.h"
int debug = 0;
#include "dhcp.h"
#include "phantap-learn.h"

#define OPT_ARGS "b:c:i:v:"

// Filter ethernet/IPv4 broadcast, a subset of IPv4 mulitcast (we only want local & low traffic multicast),
// and ethernet IPv4 ARP packets (we never know). Exclude tagged traffic as libpcap/linux include it by default
#define BPFFILTER1 "\
(\
       (ip and ether broadcast) \
    or (ip dst 0.0.0.0) \
    or (ip dst 255.255.255.255) \
    or (ip dst net 224.0.0.0/24) \
    or (ip dst net 239.255.255.0/24)"

#define BPFFILTER2_1 " or (ip and src portrange 1-1024) "

#define BPFFILTER2_DHCP " or (ip and src port 67) "

#define BPFFILTER2_DNS " or (ip and src port 53) "

#define BPFFILTER3 "\
    or (arp[0:2] = 0x0001 and arp[2:2] = 0x0800) \
) and not vlan"

#define DNS_SERVER_PORT 53
#define NTP_SERVER_PORT 123

struct netinfo cur_ni = {};
pcap_t *pcap_handle = NULL;
char *exec_block_net = NULL;
char *exec_conf_net = NULL;
char *interface = NULL;

static void usage(void)
{
    fprintf(stderr, "phantap-learn <options>\n");
    fprintf(stderr, "  -b <exec_block_net>\tthe command to run to block network traffic\n");
    fprintf(stderr, "  -c <exec_conf_net>\tthe command to run on network conf changes\n");
    fprintf(stderr, "  -i <listen-interface>\tthe interface to listen on\n");
    fprintf(stderr, "  -v <debug-level>\tprint some debug info (level > 0)\n");
    fprintf(stderr, "\nTo show/flush neigh/route\n"
                    "ip neigh show nud permanent\n"
                    "ip neigh flush nud permanent\n"
                    "ip route show proto " PHANTAP_RTPROTO "\n"
                    "ip route flush proto " PHANTAP_RTPROTO "\n");
}

static void handle_neighbour(const struct ether_addr *mac, const struct in_addr *ip, bool arp)
{
    if (!IN_ADDR_NORMAL(*ip) || !ETHER_ADDR_NORMAL(mac))
    {
        // we don't want to add multicast / broadcast to the neigboor
        return;
    }

    if (IN_ADDR_EQ(cur_ni.victim_ip, (*ip)) && ETHER_CMP(&cur_ni.victim_mac, mac) != 0)
    {
        cur_ni.changed = true;
        ETHER_CPY(&cur_ni.victim_mac, mac);
        DEBUG(1, "Victim MAC: %s\n", ether_ntoa(&cur_ni.victim_mac));
    }
    if (IN_ADDR_EQ(cur_ni.gateway_ip, (*ip)) && ETHER_CMP(&cur_ni.gateway_mac, mac) != 0)
    {
        cur_ni.changed = true;
        ETHER_CPY(&cur_ni.gateway_mac, mac);
        DEBUG(1, "Gateway MAC: %s\n", ether_ntoa(&cur_ni.gateway_mac));
    }

    if (arp == true && ETHER_CMP(&cur_ni.gateway_mac, mac) == 0 && !IN_ADDR_EQ(cur_ni.gateway_ip, (*ip)))
    {
        cur_ni.changed = true;
        cur_ni.gateway_ip.s_addr = ip->s_addr;
        DEBUG(1, "Gateway IP: %s\n", inet_ntoa(cur_ni.gateway_ip));
    }

    if (arp == false && (ETHER_ZERO(&cur_ni.gateway_mac) || ETHER_CMP(&cur_ni.gateway_mac, mac) == 0))
    {
        // we don't want to add fake neighbour like gateway_mac / public_ip
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

// response from a service extremely unlikely to run on the victim
// it might run on the gateway, so we can only infer victim mac/ip
static void _handle_response(const struct ether_header *eth_hdr, const struct ip *ip_hdr)
{
    if (IN_ADDR_NORMAL(ip_hdr->ip_dst) && ETHER_ADDR_NORMAL(eth_hdr->ether_dhost) &&
        !IN_ADDR_EQ(cur_ni.victim_ip, ip_hdr->ip_dst))
    {
        cur_ni.changed = true;
        ETHER_CPY(&cur_ni.victim_mac, eth_hdr->ether_dhost);
        cur_ni.victim_ip = ip_hdr->ip_dst;
    }
}

static void handle_dns(const struct ether_header *eth_hdr, const struct ip *ip_hdr)
{
    if (!IN_ADDR_EQ(cur_ni.dns, ip_hdr->ip_src))
    {
        cur_ni.changed = true;
        cur_ni.dns = ip_hdr->ip_src;
        DEBUG(1, "DNS Server: %s\n", inet_ntoa(cur_ni.dns));
        _handle_response(eth_hdr, ip_hdr);
    }
}

static void handle_ntp(const struct ether_header *eth_hdr, const struct ip *ip_hdr)
{
    if (!IN_ADDR_EQ(cur_ni.ntp, ip_hdr->ip_src))
    {
        cur_ni.ntp = ip_hdr->ip_src;
        DEBUG(1, "NTP Server: %s\n", inet_ntoa(cur_ni.ntp));
        _handle_response(eth_hdr, ip_hdr);
    }
}

static void snappendf(char *buf, size_t maxlen, const char *format, ...)
{
    size_t curlen = strlen(buf);
    va_list args;
    va_start(args, format);
    vsnprintf(buf + curlen, maxlen - curlen, format, args);
    va_end(args);
}

static void print_netinfo(char *buf, size_t maxlen)
{
    buf[0] = '\0';
    snappendf(buf, maxlen, "P_VICTIM_MAC=%s ", ether_ntoa(&cur_ni.victim_mac));
    snappendf(buf, maxlen, "P_VICTIM_IP=%s ", inet_ntoa(cur_ni.victim_ip));
    snappendf(buf, maxlen, "P_NETMASK=%s ", inet_ntoa(cur_ni.victim_netmask));
    snappendf(buf, maxlen, "P_GATEWAY_MAC=%s ", ether_ntoa(&cur_ni.gateway_mac));
    snappendf(buf, maxlen, "P_GATEWAY_IP=%s ", inet_ntoa(cur_ni.gateway_ip));
    snappendf(buf, maxlen, "P_DNS=%s ", inet_ntoa(cur_ni.dns));
    snappendf(buf, maxlen, "P_NTP=%s", inet_ntoa(cur_ni.ntp));
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

void block_traffic()
{
    DEBUG(1, "block_traffic()\n");
    DEBUG(2, "Executing '%s' ...\n", exec_block_net);
    if (system(exec_block_net))
        ERROR("Executing '%s' failed!!\n", exec_block_net);
}

static void set_network()
{
    cur_ni.changed = false;
    if (ETHER_ZERO(&cur_ni.victim_mac))
    {
        DEBUG(1, "set_network: We don't know victim_mac yet\n");
        return;
    }
    if (ntohl(cur_ni.victim_ip.s_addr) == INADDR_ANY)
    {
        ERROR("set_network: We don't know victim_ip, this should not happen\n");
        return;
    }
    if (ETHER_ZERO(&cur_ni.gateway_mac))
    {
        DEBUG(1, "set_network: We don't know gateway_mac yet\n");
        return;
    }

    char sbuf[1000];
    print_netinfo(sbuf, sizeof(sbuf));
    DEBUG(1, "set_network: %s\n", sbuf);
    snappendf(sbuf, sizeof(sbuf), " %s", exec_conf_net);
    DEBUG(2, "Executing '%s' ...\n", sbuf);
    if (system(sbuf))
        ERROR("Executing '%s' failed!!\n", sbuf);

    // Capture less traffic after initial detection
    if (cur_ni.dhcp == true || ntohl(cur_ni.dns.s_addr) != INADDR_ANY)
    {
        DEBUG(1, "set_network: loading new BPF filter (dhcp only)\n");
        set_bpf_filter(BPFFILTER1 BPFFILTER2_DHCP BPFFILTER3);
    }
    else
    {
        DEBUG(1, "set_network: loading new BPF filter (dhcp and dns)\n");
        set_bpf_filter(BPFFILTER1 BPFFILTER2_DHCP BPFFILTER2_DNS BPFFILTER3);
    }
}

static void set_gateway_mac(const struct ether_header *eth_hdr, const struct ip *ip_hdr)
{
    if (!ETHER_ZERO(&cur_ni.gateway_mac))
    {
        // gateway_mac already set
        return;
    }

    if (!IN_ADDR_NORMAL(ip_hdr->ip_src) || !IN_ADDR_NORMAL(ip_hdr->ip_dst))
    {
        // ignoring
        return;
    }

    if (!IN_SAME_NET(ip_hdr->ip_src, ip_hdr->ip_dst, 0xff000000))
    {
        // src and dst are not in the same /8
        if (IN_ADDR_EQ(cur_ni.victim_ip, ip_hdr->ip_src))
        {
            cur_ni.changed = true;
            ETHER_CPY(&cur_ni.gateway_mac, eth_hdr->ether_dhost);
        }
        if (IN_ADDR_EQ(cur_ni.victim_ip, ip_hdr->ip_dst))
        {
            cur_ni.changed = true;
            ETHER_CPY(&cur_ni.gateway_mac, eth_hdr->ether_shost);
        }
    }
}

static void handle_packet_ip(const struct ether_header *eth_hdr, const uint32_t caplen)
{
    if (caplen < sizeof(struct ether_header) + sizeof(struct ip))
    {
        ERROR("Capture too short for IP (%u)\n", caplen);
        return;
    }
    const struct ip *ip_hdr = (struct ip *)(eth_hdr + 1);

    if ((ntohs(ip_hdr->ip_off) & IP_OFFMASK) != 0)
    {
        DEBUG(2, "Skipping ip packet fragments\n");
        goto ethertype_ip_end;
    }
    switch (ip_hdr->ip_p)
    {
    case IPPROTO_UDP:
        if (caplen < sizeof(struct ether_header) + ip_hdr->ip_hl * 4 + sizeof(struct udphdr))
        {
            ERROR("Capture too short for UDP (%u)\n", caplen);
            goto ethertype_ip_end;
        }
        const struct udphdr *udp_hdr = (struct udphdr *)(((uint32_t *)ip_hdr) + ip_hdr->ip_hl);
        DEBUG(2, "UDP: src=%u dst=%u\n", ntohs(udp_hdr->uh_sport), ntohs(udp_hdr->uh_dport));
        // we only want DNS responses
        if (ntohs(udp_hdr->uh_sport) == DNS_SERVER_PORT)
            handle_dns(eth_hdr, ip_hdr);
        // we only want NTP responses
        if (ntohs(udp_hdr->uh_sport) == NTP_SERVER_PORT)
            handle_ntp(eth_hdr, ip_hdr);
        // we only want DHCP responses
        if (ntohs(udp_hdr->uh_sport) == DHCP_SERVER_PORT && ntohs(udp_hdr->uh_dport) == DHCP_CLIENT_PORT)
            handle_dhcp((struct dhcp_packet *)(udp_hdr + 1), ((uint8_t *)eth_hdr) + caplen);
        break;
    case IPPROTO_TCP:
        if (caplen < sizeof(struct ether_header) + ip_hdr->ip_hl * 4 + sizeof(struct tcphdr))
        {
            ERROR("Capture too short for TCP (%u)\n", caplen);
            goto ethertype_ip_end;
        }
        const struct tcphdr *th = (struct tcphdr *)(((uint32_t *)ip_hdr) + ip_hdr->ip_hl);
        DEBUG(2, "TCP: src=%u dst=%u\n", ntohs(th->th_sport), ntohs(th->th_dport));
        // we only want DNS responses
        if (ntohs(th->th_sport) == DNS_SERVER_PORT)
            handle_dns(eth_hdr, ip_hdr);
        break;
    default:
        DEBUG(2, "Unknown IP proto %#04x\n", ip_hdr->ip_p);
    }
ethertype_ip_end:
    set_gateway_mac(eth_hdr, ip_hdr);
    handle_neighbour((struct ether_addr *)eth_hdr->ether_shost, &ip_hdr->ip_src, false);
    handle_neighbour((struct ether_addr *)eth_hdr->ether_dhost, &ip_hdr->ip_dst, false);
}

static void handle_packet_arp(const struct ether_header *eth_hdr, const uint32_t caplen)
{
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
    handle_neighbour((struct ether_addr *)(arp->arp_sha), (struct in_addr *)(arp->arp_spa), true);
    handle_neighbour((struct ether_addr *)(arp->arp_tha), (struct in_addr *)(arp->arp_tpa), true);
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
        handle_packet_ip(eth_hdr, caplen);
        break;
    case ETHERTYPE_ARP:
        handle_packet_arp(eth_hdr, caplen);
        break;
    default:
        // we should never get there based of the current BPF filter
        ERROR("Unknown ethertype %#06x\n", ntohs(eth_hdr->ether_type));
    }
    if (cur_ni.changed == true)
        set_network();
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
        case 'b':
            exec_block_net = optarg;
            break;
        case 'c':
            exec_conf_net = optarg;
            break;
        case 'i':
            interface = optarg;
            break;
        case 'v':
            debug = atoi(optarg);
            break;
        }
    }

    if (exec_block_net == NULL)
    {
        ERROR("exec_block_net (-b) is mandatory !!!\n\n");
        usage();
        goto exit_err;
    }

    if (exec_conf_net == NULL)
    {
        ERROR("exec_conf_net (-c) is mandatory !!!\n\n");
        usage();
        goto exit_err;
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

    // Capture full ethernet frame
    // TODO: confirm that when using bridge there is no packet bigger then ETH_FRAME_LEN (GRO ...)
    pcap_set_snaplen(pcap_handle, ETH_FRAME_LEN);

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

    if (set_bpf_filter(BPFFILTER1 BPFFILTER2_1 BPFFILTER3) == false)
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
