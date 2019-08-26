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

#ifndef __DHCP_H
#define __DHCP_H

#include "dhcp-protocol.h"

void handle_dhcp(const struct dhcp_packet *dhcp_pkt, const uint8_t *end);

#endif
