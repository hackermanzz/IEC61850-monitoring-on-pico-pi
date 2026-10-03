#ifndef LWIPOPTS_H
#define LWIPOPTS_H

#define NO_SYS                         1

#define LWIP_SOCKET                    0
#define LWIP_NETCONN                   0

#define LWIP_TCP                       1

#define LWIP_IPV4                      1
#define LWIP_IPV6                      0

#define LWIP_DNS                       1

#define MEM_LIBC_MALLOC                0

#define LWIP_MALLOC_MEMPOOL            1

#define TCP_MSS                        1460

#define TCP_WND                        (8 * TCP_MSS)

#define TCP_SND_BUF                    (8 * TCP_MSS)

#define TCP_SND_QUEUELEN               ((4 * TCP_SND_BUF) / TCP_MSS)

/* Must be >= TCP_SND_QUEUELEN */
#define MEMP_NUM_TCP_SEG               32

#define LWIP_ALTCP                     1
#define LWIP_ALTCP_TLS                 1

#define LWIP_NETIF_STATUS_CALLBACK     1
#define LWIP_NETIF_LINK_CALLBACK       1

#define LWIP_DHCP                      1

#define LWIP_DNS_SECURE                0

#endif