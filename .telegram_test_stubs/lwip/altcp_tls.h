#ifndef TELEGRAM_STUB_ALTCP_TLS_H
#define TELEGRAM_STUB_ALTCP_TLS_H

#include "lwip/altcp.h"

struct altcp_tls_config
{
    int unused;
};

struct altcp_tls_config *altcp_tls_create_config_client(const uint8_t *cert,
                                                        size_t cert_length);
struct altcp_pcb *altcp_tls_new(struct altcp_tls_config *config,
                                unsigned char ip_type);
void *altcp_tls_context(struct altcp_pcb *pcb);

#endif
