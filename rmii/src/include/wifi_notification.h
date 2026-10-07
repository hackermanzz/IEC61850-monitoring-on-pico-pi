#ifndef WIFI_NOTIFICATION_H
#define WIFI_NOTIFICATION_H

#include <stdbool.h>
#include <stdint.h>

#define WIFI_NOTIFICATION_MESSAGE_CAPACITY (768U)

/*
 * Initialize and service from core 0. These calls are serialized with the
 * CYW43/lwIP lock; service advances one bounded network step and does not wait
 * for a network event. Submit copies the message into owned request storage
 * before returning. Pico SDK mbedTLS allocates handshake and record buffers
 * during TLS setup from its allocator, not lwIP's packet heap.
 */

typedef enum
{
    WIFI_NOTIFICATION_RESULT_NONE = 0,
    WIFI_NOTIFICATION_RESULT_WIFI,
    WIFI_NOTIFICATION_RESULT_DNS,
    WIFI_NOTIFICATION_RESULT_TLS,
    WIFI_NOTIFICATION_RESULT_HTTP,
    WIFI_NOTIFICATION_RESULT_API,
    WIFI_NOTIFICATION_RESULT_TIMEOUT,
    WIFI_NOTIFICATION_RESULT_REQUEST
} wifi_notification_result_t;

typedef struct
{
    bool                       stack_ready;
    bool                       wifi_connected;
    bool                       busy;
    uint32_t                   succeeded;
    uint32_t                   failed;
    uint16_t                   last_http_status;
    wifi_notification_result_t last_result;
} wifi_notification_status_t;

bool wifi_notification_init (void);
bool wifi_notification_submit (const char * message);
void wifi_notification_service (void);
void wifi_notification_get_status (wifi_notification_status_t * status);

#endif
