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

#ifndef __NETLINK_H
#define __NETLINK_H

#include <linux/version.h>
#include <linux/rtnetlink.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netlink/attr.h>
#include <netlink/msg.h>
#include <netlink/socket.h>

struct nl_sock *create_nl_sock();
int update_neighbour4(struct nl_sock *nl_sock, const struct ether_addr *mac, const struct in_addr *ip, uint ifindex);
int update_route4(struct nl_sock *nl_sock, const struct in_addr *ip, uint ifindex);

#endif
