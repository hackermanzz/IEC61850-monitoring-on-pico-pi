#ifndef TELEGRAM_STUB_CYW43_ARCH_H
#define TELEGRAM_STUB_CYW43_ARCH_H

#include "lwip/ip_addr.h"

#define CYW43_ITF_STA (0U)
#define CYW43_LINK_DOWN (0)
#define CYW43_LINK_JOIN (1)
#define CYW43_LINK_NOIP (2)
#define CYW43_LINK_UP (3)
#define CYW43_AUTH_WPA2_AES_PSK (0x204U)

typedef struct
{
    int unused;
} cyw43_t;

extern cyw43_t cyw43_state;
int            cyw43_arch_init (void);
void           cyw43_arch_enable_sta_mode (void);
int  cyw43_arch_wifi_connect_async (const char * ssid, const char * password,
                                    unsigned int auth);
int  cyw43_wifi_link_status (cyw43_t * state, unsigned int interface);
int  cyw43_tcpip_link_status (cyw43_t * state, unsigned int interface);
void cyw43_arch_lwip_begin (void);
void cyw43_arch_lwip_end (void);

#endif
