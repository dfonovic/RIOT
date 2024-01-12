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
#include "net/nanocoap.h"


#define COAP_INBUF_SIZE (256U)

#define MAIN_QUEUE_SIZE     (8)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

void send_coap_multicast_request(void)
{
    /* Define the multicast address */
    sock_udp_ep_t remote = { .family = AF_INET6 };
    if (ipv6_addr_from_str((ipv6_addr_t *)&remote.addr.ipv6, "ff02::1") == NULL) {
        puts("Error: unable to parse destination address");
        return;
    }
    remote.port = COAP_PORT;

    /* Create the CoAP request */
    uint8_t buf[128];
    coap_pkt_t pdu;
    pdu.hdr = (coap_hdr_t *)buf;
    //pdu.hdr->id = htons(id);
    pdu.payload = buf + 4;
    pdu.payload_len = sizeof(buf) - (pdu.payload - buf);
    //pdu.payload_len = 0;
    coap_build_hdr(pdu.hdr, COAP_TYPE_NON, NULL,  0, COAP_METHOD_GET, random_uint32());
    coap_pkt_init(&pdu, buf, sizeof(buf), 4);
    //pdu.hdr->type = COAP_TYPE_NON;
    //pdu.hdr->id = htons(random_uint32());

    //coap_hdr_set_type(pdu.hdr, COAP_TYPE_NON);
    //coap_hdr_set_code(pdu.hdr, COAP_METHOD_GET);
    //coap_hdr_set_id(pdu.hdr, nanocoap_request_id());
    //coap_opt_add_uri_path(&pdu, "/random-data");
    coap_opt_add_uri_path(&pdu, "/riot/board");
    

    size_t len = coap_opt_finish(&pdu, COAP_OPT_FINISH_PAYLOAD);

    /* Send the CoAP request */
    ssize_t res = sock_udp_send(NULL, pdu.hdr, len, &remote);
    if (res <= 0) {
        puts("Error: unable to send CoAP request");
    }

    /* Receive the response */
    // Declare the sock variable
    /* Create a buffer to hold the response */
    uint8_t rcv[128];
    //sock_udp_t sock;
    sock_udp_t sock_udp;
    sock_udp_t *sock = &sock_udp;

    // ...

    // Use the sock variable in sock_udp_recv
    
    res = sock_udp_recv(sock, rcv, sizeof(rcv), SOCK_NO_TIMEOUT, &remote);
    if (res <= 0) {
        if (res == -ETIMEDOUT) {
            puts("CoAP request timed out");
        } else {
            printf("Error receiving CoAP response: %d\n", (int)res);
        }
    } else {
        coap_pkt_t pkt;
        if (coap_parse(&pkt, rcv, res) < 0) {
            puts("Error parsing CoAP response");
        } else {
            /* Handle the CoAP response */
            if (coap_get_type(&pkt) == COAP_CODE_CONTENT) {
                /* The response contains content, print it */
                printf("Received CoAP response: %.*s\n", pkt.payload_len, pkt.payload);
            } 
            
            //else 
            //{
                /* The response does not contain content, print the response code */
            //    printf("Received CoAP response with code %u\n", coap_get_code(&pkt));
            //}            
        }
    }
    
}

int main(void)
{
    puts("RIOT nanocoap client send multicast application");

    /* nanocoap_server uses gnrc sock which uses gnrc which needs a msg queue */
    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);

    puts("Waiting for address autoconfiguration...");
    xtimer_sleep(3);

    /* print network addresses */
    printf("{\"IPv6 addresses\": [\"");
    netifs_print_ipv6("\", \"");
    puts("\"]}");
    //setup_multicast_listener();
    while (1) {
        send_coap_multicast_request();
        xtimer_sleep(10);
    }
    //send_coap_multicast_request();

    

    /* initialize nanocoap server instance */
    //uint8_t buf[COAP_INBUF_SIZE];
    //sock_udp_ep_t local = { .port=COAP_PORT, .family=AF_INET6 };
    //nanocoap_server(&local, buf, sizeof(buf));

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
