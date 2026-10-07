#ifndef TELEGRAM_STUB_DNS_H
#define TELEGRAM_STUB_DNS_H

#include "lwip/altcp.h"

typedef void (*dns_found_callback_t)(const char *, const ip_addr_t *, void *);
err_t dns_gethostbyname(const char *name,
                        ip_addr_t *address,
                        dns_found_callback_t callback,
                        void *argument);

#endif
