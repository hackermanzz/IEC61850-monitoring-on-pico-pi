/*
 * Copyright (c) 2001-2003 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 * EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Simon Goldschmidt
 *
 */
#ifndef PICO_IEC61850_LWIPOPTS_H
#define PICO_IEC61850_LWIPOPTS_H

/*
 * Shared lwIP configuration for the RMII analyzer and the Pico W Telegram
 * client. The project runs lwIP without an operating system.
 */
#define NO_SYS 1
#define MEM_ALIGNMENT 4
#ifndef MEM_SIZE
#define MEM_SIZE (16 * 1024)
#endif

/* The threadsafe-background CYW43 architecture cannot use libc malloc. */
#if PICO_CYW43_ARCH_POLL
#define MEM_LIBC_MALLOC 1
#else
#define MEM_LIBC_MALLOC 0
#endif
/* Use lwIP's bounded heap. LWIP_MALLOC_MEMPOOL is a declaration macro,
 * not a Boolean option; custom pools are not configured in this project. */

#define LWIP_ARP 1
#define LWIP_ETHERNET 1
#define LWIP_RAW 1
#define LWIP_NETCONN 0
#define LWIP_SOCKET 0
#define LWIP_DHCP 1
#define LWIP_ICMP 1
#define LWIP_UDP 1
#define LWIP_TCP 1

#define LWIP_ALTCP 1
#define LWIP_ALTCP_TLS 1
#define LWIP_ALTCP_TLS_MBEDTLS 1
/* lwIP's default is VERIFY_OPTIONAL; fail closed on certificate errors. */
#define ALTCP_MBEDTLS_AUTHMODE MBEDTLS_SSL_VERIFY_REQUIRED
#ifndef MEMP_NUM_ALTCP_PCB
#define MEMP_NUM_ALTCP_PCB 4
#endif


#define ETH_PAD_SIZE 0

#define LWIP_IPV4 1
#define LWIP_IPV6 0
#define LWIP_DNS 1
/* Keep the upstream DNS randomization and matching safeguards enabled. */

#define LWIP_NETIF_LINK_CALLBACK 1
#define LWIP_NETIF_STATUS_CALLBACK 1
#define LWIP_NETIF_HOSTNAME 1
#define LWIP_NETIF_TX_SINGLE_PBUF 1
#define LWIP_TCP_KEEPALIVE 1
#define LWIP_CHKSUM_ALGORITHM 3
#define DHCP_DOES_ARP_CHECK 0
#define LWIP_DHCP_DOES_ACD_CHECK 0

#define TCP_MSS (1460)
#define TCP_WND (8 * TCP_MSS)
#define TCP_SND_BUF (8 * TCP_MSS)
#define TCP_SND_QUEUELEN ((4 * TCP_SND_BUF) / TCP_MSS)
#define MEMP_NUM_TCP_SEG 48
#define MEMP_NUM_ARP_QUEUE 10
/* Passive RMII frames never enter lwIP. Reserve pbufs for Wi-Fi only and
 * leave RAM for the RF waveform histories, packet evidence, and TLS heap. */
#define PBUF_POOL_SIZE 8


#define LWIP_HTTPD_CGI 0
#define LWIP_HTTPD_SSI 0
#define LWIP_HTTPD_SSI_INCLUDE_TAG 0

/* Keep TLS diagnostics available during the integration. */
#define LWIP_DEBUG 1
#define ALTCP_MBEDTLS_DEBUG LWIP_DBG_OFF
#ifndef NDEBUG
#define LWIP_STATS 1
#define LWIP_STATS_DISPLAY 1
#endif

#if 0
#define LWIP_DEBUG 1
#define TCP_DEBUG LWIP_DBG_ON
#define ETHARP_DEBUG LWIP_DBG_ON
#define PBUF_DEBUG LWIP_DBG_ON
#define IP_DEBUG LWIP_DBG_ON
#define TCPIP_DEBUG LWIP_DBG_ON
#define DHCP_DEBUG LWIP_DBG_ON
#define UDP_DEBUG LWIP_DBG_ON
#endif

#endif /* PICO_IEC61850_LWIPOPTS_H */
