/** @file lwipopts.h
 * @brief SDK polled NO_SYS networking, owned by one Core0 task.
 * Derived from the Pico1 notification branch; see wifi/README provenance.
 * lwIP uses its own16KiB arena; TLS uses a separate fixed arena.
 */
#ifndef LWIP_LWIPOPTS_H
#define LWIP_LWIPOPTS_H

#define NO_SYS               1
#define LWIP_SOCKET          0
#define LWIP_NETCONN         0
#define SYS_LIGHTWEIGHT_PROT 0

/* lwip/arch.h otherwise falls back to <ctype.h>, whose classic BSD/newlib
 * implementation #defines bare _B/_C/_L/_N/_P/_S/_U/_X bitmask macros for
 * its internal character-class table. tk/typedef.h uses those exact names
 * (_B, _H, _W, _D, ...) as volatile-qualified type names, so any file that
 * ends up seeing both (e.g. mqtt_utk.c, which needs lwip/apps/mqtt.h and
 * tm/tmonitor.h together) fails to parse tk/typedef.h with something like
 * "expected identifier ... before numeric constant". LWIP_NO_CTYPE_H makes
 * lwip/arch.h use its own inline lwip_isdigit()-style helpers instead. */
#define LWIP_NO_CTYPE_H 1

#define MEM_LIBC_MALLOC 0
#define MEM_ALIGNMENT   4
#define MEM_SIZE        (16 * 1024)

#define MEMP_NUM_TCP_SEG   32
#define MEMP_NUM_ARP_QUEUE 10
#define PBUF_POOL_SIZE     24

/* lwIP's default is exactly LWIP_NUM_SYS_TIMEOUT_INTERNAL -- only what the
 * enabled core features (TCP, ARP, DHCP, DNS, reassembly) need for
 * themselves, with nothing spare for anything built on top. Every
 * sys_timeout() user above the stack has to be added here or the pool runs
 * dry and lwip_utk_assert() halts with "pool MEMP_SYS_TIMEOUT is empty":
 * mqtt.c arms its own cyclic keepalive timer per client, and mqtt_utk.c adds
 * the heartbeat chain plus a connect-retry timer. Four covers those with
 * room to spare; each slot is only a few bytes. */
#define MEMP_NUM_SYS_TIMEOUT (LWIP_NUM_SYS_TIMEOUT_INTERNAL + 4)

#define LWIP_ARP      1
#define LWIP_ETHERNET 1
#define LWIP_ICMP     1
#define LWIP_RAW      1

#define TCP_MSS          1460
#define TCP_WND          (8 * TCP_MSS)
#define TCP_SND_BUF      (8 * TCP_MSS)
#define TCP_SND_QUEUELEN ((4 * (TCP_SND_BUF) + (TCP_MSS - 1)) / (TCP_MSS))

#define LWIP_NETIF_STATUS_CALLBACK 1
#define LWIP_NETIF_LINK_CALLBACK   1
#define LWIP_NETIF_HOSTNAME        1
#define LWIP_NETIF_TX_SINGLE_PBUF  1

#define LWIP_CHKSUM_ALGORITHM 3

#define LWIP_IPV4                1
#define LWIP_DHCP                1
#define DHCP_DOES_ARP_CHECK      0
#define LWIP_DHCP_DOES_ACD_CHECK 0

#define LWIP_TCP           1
#define LWIP_UDP           1
#define LWIP_DNS           1
#define LWIP_TCP_KEEPALIVE 1

#define MEM_STATS          0
#define SYS_STATS          0
#define MEMP_STATS         0
#define LINK_STATS         0
#define LWIP_STATS         0
#define LWIP_STATS_DISPLAY 0

#define LWIP_DEBUG 0

/* SDK polling backend: one Core0 task, no TCP/IP thread. */
#define LWIP_ALTCP             1
#define LWIP_ALTCP_TLS         1
#define LWIP_ALTCP_TLS_MBEDTLS 1
#define ALTCP_MBEDTLS_AUTHMODE MBEDTLS_SSL_VERIFY_REQUIRED
/* Automatic bootstrap time on the same radio owner; no extra task/socket API.
 * Checks source address/port and matches the reply's request timestamp.
 * SNTP is not authenticated; TLS chain/hostname verification stays required.
 */
#include "wifi_time.h"
#define MEMP_NUM_UDP_PCB              6
#define SNTP_SERVER_DNS               1
#define SNTP_MAX_SERVERS              2
#define SNTP_CHECK_RESPONSE           2
#define SNTP_GET_SYSTEM_TIME(sec, us) wifi_time_get_sntp(&(sec), &(us))
#define SNTP_SET_SYSTEM_TIME(sec)     wifi_time_set_sntp((uint32_t) (sec))

/* The radio task must never acquire the consumer's stdio/libc state. */
#define LWIP_PLATFORM_DIAG(x)                                                  \
    do                                                                         \
    {                                                                          \
    } while (0)

#endif /* LWIP_LWIPOPTS_H */

/*** end of file ***/
