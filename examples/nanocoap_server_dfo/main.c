/*
 * Copyright (C) 2016 Kaspar Schleiser <kaspar@schleiser.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       CoAP example server application (using nanocoap)
 *
 * @author      Kaspar Schleiser <kaspar@schleiser.de>
 * @}
 */

#include <stdio.h>

#include "net/nanocoap_sock.h"
#include "xtimer.h"
#include "net/gnrc/netif.h"
#include "net/gnrc/ipv6/nib.h"
#include "net/gnrc/netif/hdr.h"
#include "net/gnrc/ipv6.h"
#include "net/gnrc/netif/raw.h"
#include "net/gnrc.h"
#include "net/gnrc/netreg.h"
#include "net/gnrc/pktbuf.h"
#include "net/sock/udp.h"
#include "net/nanocoap_sock.h"

#define COAP_INBUF_SIZE (256U)

#define MAIN_QUEUE_SIZE     (8)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

void setup_multicast_listener(void);

int main(void)
{
    puts("RIOT nanocoap example application");

    /* nanocoap_server uses gnrc sock which uses gnrc which needs a msg queue */
    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);

    puts("Waiting for address autoconfiguration...");
    xtimer_sleep(3);

    /* print network addresses */
    printf("{\"IPv6 addresses\": [\"");
    netifs_print_ipv6("\", \"");
    puts("\"]}");
    setup_multicast_listener();
    

    /* initialize nanocoap server instance */
    uint8_t buf[COAP_INBUF_SIZE];
    sock_udp_ep_t local = { .port=COAP_PORT, .family=AF_INET6 };
    nanocoap_server(&local, buf, sizeof(buf));

    /* should be never reached */
    return 0;
}

void setup_multicast_listener(void)
{
    /* Set up the multicast address to listen on */
    ipv6_addr_t multicast_addr;
    if (ipv6_addr_from_str(&multicast_addr, "ff02::1") == NULL) {
        puts("Error: unable to parse multicast address");
        return;
    }

    gnrc_netif_t *netif = gnrc_netif_iter(NULL);
    if (netif == NULL) {
        puts("Error: no network interface found");
        return;
    }

    if (gnrc_netif_ipv6_group_join(netif, &multicast_addr) < 0) {
        puts("Error: unable to join multicast group");
        return;
    }

    puts("Successfully joined multicast group");
}
