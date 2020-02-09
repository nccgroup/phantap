/*
 * Copyright (C) 2020 Diana Dragusin <diana.dragusin@nccgroup.com>
 * Copyright (C) 2020 Etienne Champetier <champetier.etienne@gmail.com>
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
#include "netlink.h"
#include "common.h"

struct nl_sock *create_nl_sock()
{
    struct nl_sock *nl_sock = nl_socket_alloc();
    if (nl_sock == NULL)
        return NULL;

    if (nl_connect(nl_sock, NETLINK_ROUTE) >= 0)
        return nl_sock;

    nl_socket_free(nl_sock);
    return NULL;
}

int update_neighbour4(struct nl_sock *nl_sock, const struct ether_addr *mac, const struct in_addr *ip, uint ifindex) {
    struct nl_msg *msg = nlmsg_alloc_simple(RTM_NEWNEIGH, NLM_F_REPLACE|NLM_F_CREATE);
    if (!msg)
        return -1;

    struct ndmsg ndm = {
        .ndm_family = AF_INET,
        .ndm_ifindex = ifindex,
        .ndm_state=NUD_PERMANENT,
        .ndm_flags=0,
        .ndm_type=RTN_UNSPEC
    };
    nlmsg_append(msg, &ndm, sizeof(ndm), 0);
    nla_put(msg, NDA_DST, sizeof(*ip), ip);
    nla_put(msg, NDA_LLADDR, sizeof(*mac), mac);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0)
    nla_put_u8(msg, NDA_PROTOCOL, PHANTAP_RTPROTO);
#endif

    int ret = nl_send_auto_complete(nl_sock, msg);
    nlmsg_free(msg);
    if (ret < 0)
        return ret;

    return nl_wait_for_ack(nl_sock);
}

int update_route4(struct nl_sock *nl_sock, const struct in_addr *ip, uint ifindex) {
    struct nl_msg *msg = nlmsg_alloc_simple(RTM_NEWROUTE, NLM_F_REPLACE|NLM_F_CREATE);
    if (!msg)
        return -1;

    struct rtmsg rtm = {
        .rtm_family = AF_INET,
        .rtm_dst_len = 32,
        .rtm_src_len = 0,
        .rtm_tos=0,
        .rtm_table=RT_TABLE_MAIN,
        .rtm_protocol=PHANTAP_RTPROTO,
        .rtm_scope=RT_SCOPE_LINK,
        .rtm_type=RTN_UNICAST,
    };
    nlmsg_append(msg, &rtm, sizeof(rtm), 0);
    nla_put(msg, RTA_DST, sizeof(*ip), ip);
    nla_put_u32(msg, RTA_OIF, ifindex);

    int ret = nl_send_auto_complete(nl_sock, msg);
    nlmsg_free(msg);
    if (ret < 0)
        return ret;

    return nl_wait_for_ack(nl_sock);
}
