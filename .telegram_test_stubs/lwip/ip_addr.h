#ifndef TELEGRAM_STUB_IP_ADDR_H
#define TELEGRAM_STUB_IP_ADDR_H

typedef struct
{
    unsigned int value;
} ip_addr_t;

#define IPADDR_TYPE_V4 (0U)
#define ip_addr_isany(address_ptr) ((address_ptr)->value == 0U)

#endif
