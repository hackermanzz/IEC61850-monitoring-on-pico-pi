#ifndef TELEGRAM_STUB_ALTCP_H
#define TELEGRAM_STUB_ALTCP_H

#include <stdint.h>
#include <stddef.h>

#include "lwip/ip_addr.h"

typedef int err_t;
typedef uint16_t u16_t;
struct altcp_pcb;
struct pbuf;
typedef err_t (*altcp_connected_fn)(void *, struct altcp_pcb *, err_t);
typedef void (*altcp_err_fn)(void *, err_t);
typedef err_t (*altcp_recv_fn)(void *, struct altcp_pcb *, struct pbuf *, err_t);

#define ERR_OK (0)
#define ERR_MEM (-1)
#define ERR_INPROGRESS (-5)
#define TCP_WRITE_FLAG_COPY (1U)

struct pbuf
{
    void *payload;
    uint16_t len;
    uint16_t tot_len;
    struct pbuf *next;
};

struct altcp_pcb
{
    altcp_err_fn error_callback;
    altcp_recv_fn receive_callback;
    altcp_connected_fn connected_callback;
    void *argument;
    char request[5000];
};

void altcp_arg(struct altcp_pcb *pcb, void *argument);
void altcp_err(struct altcp_pcb *pcb, altcp_err_fn callback);
void altcp_recv(struct altcp_pcb *pcb, altcp_recv_fn callback);
err_t altcp_connect(struct altcp_pcb *pcb,
                    const ip_addr_t *address,
                    uint16_t port,
                    altcp_connected_fn callback);
err_t altcp_write(struct altcp_pcb *pcb,
                  const void *data,
                  u16_t length,
                  uint8_t flags);
err_t altcp_output(struct altcp_pcb *pcb);
void altcp_recved(struct altcp_pcb *pcb, uint16_t length);
err_t altcp_close(struct altcp_pcb *pcb);
void altcp_abort(struct altcp_pcb *pcb);
uint16_t pbuf_free(struct pbuf *buffer);

#endif
