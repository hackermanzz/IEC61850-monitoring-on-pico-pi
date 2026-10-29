#include <stdio.h>
#include <string.h>

#include "pico/cyw43_arch.h"
#include "pico/stdlib.h"
#include "lwip/altcp.h"
#include "lwip/altcp_tls.h"
#include "lwip/dns.h"
#include "mbedtls/ssl.h"

#include "altcp_tls_mbedtls_structs.h"
#include "telegram_http_parser.h"
#include "wifi_notification.h"
#include "wifi_notification_config.h"

#define TELEGRAM_HOSTNAME "api.telegram.org"
#define TELEGRAM_PORT (443U)
#define WIFI_RETRY_INTERVAL_MS (10000U)
#define DNS_TIMEOUT_MS (10000U)
#define TLS_TIMEOUT_MS (20000U)
#define HTTP_TIMEOUT_MS (15000U)
#define SEND_TIMEOUT_MS (15000U)
#define HTTP_WRITE_CHUNK_CAPACITY (1024U)
#define TELEGRAM_TOKEN_CAPACITY (128U)
#define TELEGRAM_CHAT_ID_CAPACITY (64U)
#define TELEGRAM_CHAT_ID_ENCODED_CAPACITY (TELEGRAM_CHAT_ID_CAPACITY * 3U)
#define TELEGRAM_CA_MINIMUM_SIZE (64U)
#define TELEGRAM_ENCODED_MESSAGE_CAPACITY                                      \
    (WIFI_NOTIFICATION_MESSAGE_CAPACITY * 3U)
#define TELEGRAM_BODY_CAPACITY                                                 \
    (TELEGRAM_ENCODED_MESSAGE_CAPACITY + TELEGRAM_CHAT_ID_CAPACITY * 3U + 32U)
#define TELEGRAM_REQUEST_CAPACITY                                              \
    (TELEGRAM_BODY_CAPACITY + TELEGRAM_TOKEN_CAPACITY + 256U)
#define TELEGRAM_PREFIX_CAPACITY (TELEGRAM_CHAT_ID_CAPACITY * 3U + 32U)
#define TELEGRAM_HEADER_CAPACITY (TELEGRAM_TOKEN_CAPACITY + 256U)
#define DNS_CONTEXT_CAPACITY (4U)
#define DNS_PENDING_RETRY_MS (1000U)
#define HTTP_SUCCESS_STATUS_MIN (200U)
#define HTTP_SUCCESS_STATUS_LIMIT (300U)

typedef enum
{
    STATE_UNINITIALIZED = 0,
    STATE_WIFI_WAIT,
    STATE_DNS_WAIT,
    STATE_TLS_WAIT,
    STATE_HTTP_SEND,
    STATE_HTTP_WAIT,
    STATE_FINISH
} notification_state_t;

typedef struct
{
    bool     pending;
    uint32_t generation;
} dns_context_t;

static notification_state_t       g_state = STATE_UNINITIALIZED;
static wifi_notification_status_t g_status;
static struct altcp_pcb *         gp_https_pcb;
static struct altcp_tls_config *  gp_tls_config;
static ip_addr_t                  g_server_address;
static dns_context_t              g_dns_contexts[DNS_CONTEXT_CAPACITY];
static dns_context_t *            gp_active_dns_context;
static telegram_http_parser_t     g_http_parser;
static char                       g_http_request[TELEGRAM_REQUEST_CAPACITY];
static uint32_t                   g_next_action_ms;
static uint32_t                   g_deadline_ms;
static uint32_t                   g_dns_generation;
static size_t                     g_http_send_offset;
static size_t                     g_http_queued_length;
static bool                       g_request_queued;
static bool                       g_tls_connected;
static bool                       g_connection_failed;
static bool                       g_response_finished;
static bool                       g_response_success;
static bool                       g_close_requested;
static uint16_t                   g_response_status;
static wifi_notification_result_t g_failure_result;

static bool
deadline_reached (uint32_t deadline)
{
    return (int32_t) (to_ms_since_boot(get_absolute_time()) - deadline) >= 0;
}

static bool
wifi_link_is_up (void)
{
    /* Association reports JOIN; TCP/IP reports UP after DHCP supplies an IP. */
    return cyw43_tcpip_link_status(&cyw43_state, CYW43_ITF_STA) ==
           CYW43_LINK_UP;
}

static void
mark_failure (wifi_notification_result_t result)
{
    if (!g_status.busy)
    {
        return;
    }
    g_response_success = false;
    g_failure_result   = result;
    g_state            = STATE_FINISH;
}

static void
dns_callback (const char * name, const ip_addr_t * resolved, void * argument)
{
    dns_context_t * context = (dns_context_t *) argument;
    (void) name;
    if (context == NULL || !context->pending)
    {
        return;
    }
    context->pending = false;
    if (context != gp_active_dns_context ||
        context->generation != g_dns_generation || g_state != STATE_DNS_WAIT)
    {
        return;
    }
    gp_active_dns_context = NULL;
    if (resolved == NULL || ip_addr_isany(resolved))
    {
        mark_failure(WIFI_NOTIFICATION_RESULT_DNS);
        return;
    }
    g_server_address = *resolved;
    g_state          = STATE_TLS_WAIT;
    g_deadline_ms    = to_ms_since_boot(get_absolute_time()) + TLS_TIMEOUT_MS;
}

static err_t
connected_callback (void * argument, struct altcp_pcb * pcb, err_t error)
{
    (void) argument;
    (void) pcb;
    if (error != ERR_OK)
    {
        g_connection_failed = true;
        return error;
    }
    g_tls_connected = true;
    return ERR_OK;
}

static void
error_callback (void * argument, err_t error)
{
    (void) argument;
    (void) error;
    gp_https_pcb        = NULL;
    g_connection_failed = true;
}

static err_t
receive_callback (void * argument, struct altcp_pcb * pcb, struct pbuf * buffer,
                  err_t error)
{
    struct pbuf * segment = buffer;
    (void) argument;
    if (error != ERR_OK)
    {
        if (buffer != NULL)
        {
            pbuf_free(buffer);
        }
        mark_failure(WIFI_NOTIFICATION_RESULT_HTTP);
        return error;
    }
    if (buffer == NULL)
    {
        if (!telegram_http_parser_succeeded(&g_http_parser))
        {
            if (g_http_parser.complete &&
                g_http_parser.http_status >= HTTP_SUCCESS_STATUS_MIN &&
                g_http_parser.http_status < HTTP_SUCCESS_STATUS_LIMIT)
            {
                mark_failure(WIFI_NOTIFICATION_RESULT_API);
            }
            else
            {
                mark_failure(WIFI_NOTIFICATION_RESULT_HTTP);
            }
        }
        else
        {
            g_response_success  = true;
            g_response_finished = true;
            g_state             = STATE_FINISH;
        }
        g_close_requested = true;
        return ERR_OK;
    }
    while (segment != NULL)
    {
        if (segment->len > 0U &&
            !telegram_http_parser_feed(&g_http_parser,
                                       (const uint8_t *) segment->payload,
                                       segment->len))
        {
            mark_failure(WIFI_NOTIFICATION_RESULT_HTTP);
            break;
        }
        segment = segment->next;
    }
    if (pcb != NULL)
    {
        altcp_recved(pcb, buffer->tot_len);
    }
    pbuf_free(buffer);
    if (g_http_parser.http_status != 0U)
    {
        g_response_status = g_http_parser.http_status;
    }
    if (telegram_http_parser_succeeded(&g_http_parser))
    {
        g_response_success  = true;
        g_response_finished = true;
        g_state             = STATE_FINISH;
    }
    else if (g_http_parser.failed || g_http_parser.complete)
    {
        g_failure_result =
            !g_http_parser.failed &&
                    g_http_parser.http_status >= HTTP_SUCCESS_STATUS_MIN &&
                    g_http_parser.http_status < HTTP_SUCCESS_STATUS_LIMIT
                ? WIFI_NOTIFICATION_RESULT_API
                : WIFI_NOTIFICATION_RESULT_HTTP;
        g_response_finished = true;
        g_state             = STATE_FINISH;
    }
    return ERR_OK;
}

static void
close_transport (void)
{
    if (gp_https_pcb != NULL)
    {
        altcp_err(gp_https_pcb, NULL);
        altcp_recv(gp_https_pcb, NULL);
        if (altcp_close(gp_https_pcb) != ERR_OK)
        {
            altcp_abort(gp_https_pcb);
        }
        gp_https_pcb = NULL;
    }
    /* Keep the shared configuration alive for every future request. */
}

static bool
build_request (const char * message)
{
    char   encoded_chat_id[TELEGRAM_CHAT_ID_ENCODED_CAPACITY];
    char   body_prefix[TELEGRAM_PREFIX_CAPACITY];
    char   header[TELEGRAM_HEADER_CAPACITY];
    size_t chat_id_length         = 0U;
    size_t encoded_message_length = 0U;
    int    prefix_length          = 0;
    int    header_length          = 0;
    int    request_length         = 0;
    while (chat_id_length < TELEGRAM_CHAT_ID_CAPACITY &&
           CHATID[chat_id_length] != '\0')
    {
        chat_id_length++;
    }
    if (chat_id_length == 0U || chat_id_length >= TELEGRAM_CHAT_ID_CAPACITY ||
        !telegram_http_form_encode(encoded_chat_id, sizeof(encoded_chat_id),
                                   CHATID) ||
        !telegram_http_form_encode(g_http_request, sizeof(g_http_request),
                                   message))
    {
        return false;
    }
    encoded_message_length = strlen(g_http_request);
    prefix_length          = snprintf(body_prefix, sizeof(body_prefix),
                                      "chat_id=%s&text=", encoded_chat_id);
    if (prefix_length < 0 || (size_t) prefix_length >= sizeof(body_prefix) ||
        encoded_message_length + (size_t) prefix_length >=
            sizeof(g_http_request))
    {
        return false;
    }
    memmove(g_http_request + prefix_length, g_http_request,
            encoded_message_length + 1U);
    memcpy(g_http_request, body_prefix, (size_t) prefix_length);
    const size_t body_length = encoded_message_length + (size_t) prefix_length;
    header_length =
        snprintf(header, sizeof(header),
                 "POST /bot%s/sendMessage HTTP/1.1\r\n"
                 "Host: %s\r\n"
                 "Content-Type: application/x-www-form-urlencoded\r\n"
                 "Content-Length: %u\r\n"
                 "Connection: close\r\n\r\n",
                 TELEBOT_TOKEN, TELEGRAM_HOSTNAME, (unsigned) body_length);
    if (header_length < 0 || (size_t) header_length >= sizeof(header) ||
        body_length + (size_t) header_length >= sizeof(g_http_request))
    {
        return false;
    }
    memmove(g_http_request + header_length, g_http_request, body_length + 1U);
    memcpy(g_http_request, header, (size_t) header_length);
    request_length = header_length + (int) body_length;
    return request_length > 0 &&
           (size_t) request_length < sizeof(g_http_request);
}

static bool
start_tls_connection (void)
{
    const uint8_t * ca_certificate = (const uint8_t *) CA_ROOT_CERT;
    int             result         = 0;
    if (gp_tls_config == NULL &&
        sizeof(CA_ROOT_CERT) < TELEGRAM_CA_MINIMUM_SIZE)
    {
        mark_failure(WIFI_NOTIFICATION_RESULT_TLS);
        return false;
    }
    /* SDK mbedTLS allocates handshake and record buffers outside lwIP heap. */
    if (gp_tls_config == NULL)
    {
        /* The default client mode verifies CA and host name; this build lacks
         * a trusted RTC, so certificate date checks are not available. */
        gp_tls_config = altcp_tls_create_config_client(ca_certificate,
                                                       sizeof(CA_ROOT_CERT));
    }
    if (gp_tls_config == NULL)
    {
        mark_failure(WIFI_NOTIFICATION_RESULT_TLS);
        return false;
    }
    gp_https_pcb = altcp_tls_new(gp_tls_config, IPADDR_TYPE_V4);
    if (gp_https_pcb == NULL)
    {
        mark_failure(WIFI_NOTIFICATION_RESULT_TLS);
        return false;
    }
    result = mbedtls_ssl_set_hostname(altcp_tls_context(gp_https_pcb),
                                      TELEGRAM_HOSTNAME);
    if (result != 0)
    {
        mark_failure(WIFI_NOTIFICATION_RESULT_TLS);
        return false;
    }
    g_tls_connected     = false;
    g_connection_failed = false;
    altcp_arg(gp_https_pcb, NULL);
    altcp_err(gp_https_pcb, error_callback);
    altcp_recv(gp_https_pcb, receive_callback);
    if (altcp_connect(gp_https_pcb, &g_server_address, TELEGRAM_PORT,
                      connected_callback) != ERR_OK)
    {
        mark_failure(WIFI_NOTIFICATION_RESULT_TLS);
        return false;
    }
    return true;
}

static void
begin_dns_lookup (void)
{
    err_t           result  = ERR_OK;
    dns_context_t * context = NULL;
    size_t          index   = 0U;
    while (index < DNS_CONTEXT_CAPACITY && context == NULL)
    {
        if (!g_dns_contexts[index].pending)
        {
            context = &g_dns_contexts[index];
        }
        index++;
    }
    if (context == NULL)
    {
        mark_failure(WIFI_NOTIFICATION_RESULT_DNS);
        return;
    }
    g_dns_generation++;
    context->generation   = g_dns_generation;
    context->pending      = true;
    gp_active_dns_context = context;
    result = dns_gethostbyname(TELEGRAM_HOSTNAME, &g_server_address,
                               dns_callback, context);
    if (result == ERR_OK)
    {
        context->pending      = false;
        gp_active_dns_context = NULL;
        g_state               = STATE_TLS_WAIT;
        g_deadline_ms = to_ms_since_boot(get_absolute_time()) + TLS_TIMEOUT_MS;
    }
    else if (result == ERR_INPROGRESS)
    {
        g_state       = STATE_DNS_WAIT;
        g_deadline_ms = to_ms_since_boot(get_absolute_time()) + DNS_TIMEOUT_MS;
    }
    else
    {
        context->pending      = false;
        gp_active_dns_context = NULL;
        mark_failure(WIFI_NOTIFICATION_RESULT_DNS);
    }
}

static void
finish_request (void)
{
    close_transport();
    if (g_response_success)
    {
        g_status.succeeded++;
        g_status.last_result = WIFI_NOTIFICATION_RESULT_NONE;
    }
    else
    {
        g_status.failed++;
        g_status.last_result = g_failure_result == WIFI_NOTIFICATION_RESULT_NONE
                                   ? WIFI_NOTIFICATION_RESULT_HTTP
                                   : g_failure_result;
    }
    g_status.last_http_status = g_response_status;
    g_status.busy             = false;
    g_request_queued          = false;
    g_failure_result          = WIFI_NOTIFICATION_RESULT_NONE;
    g_response_success        = false;
    g_response_finished       = false;
    g_close_requested         = false;
    g_tls_connected           = false;
    g_connection_failed       = false;
    g_state                   = STATE_WIFI_WAIT;
    g_next_action_ms          = to_ms_since_boot(get_absolute_time()) + 1U;
}

bool
wifi_notification_init (void)
{
    int result = 0;
    if (g_status.stack_ready)
    {
        return true;
    }
    result = cyw43_arch_init();
    if (result != 0)
    {
        return false;
    }
    cyw43_arch_enable_sta_mode();
    g_status.stack_ready = true;
    g_status.last_result = WIFI_NOTIFICATION_RESULT_NONE;
    g_state              = STATE_WIFI_WAIT;
    g_next_action_ms     = to_ms_since_boot(get_absolute_time());
    return true;
}

bool
wifi_notification_submit (const char * message)
{
    size_t length  = 0U;
    bool   link_up = false;
    if (message == NULL || !g_status.stack_ready)
    {
        return false;
    }
    cyw43_arch_lwip_begin();
    if (g_status.busy)
    {
        cyw43_arch_lwip_end();
        return false;
    }
    link_up = wifi_link_is_up();
    if (!link_up)
    {
        cyw43_arch_lwip_end();
        return false;
    }
    while (length < WIFI_NOTIFICATION_MESSAGE_CAPACITY &&
           message[length] != '\0')
    {
        length++;
    }
    if (length == 0U || length >= WIFI_NOTIFICATION_MESSAGE_CAPACITY ||
        !build_request(message))
    {
        cyw43_arch_lwip_end();
        return false;
    }
    g_request_queued    = true;
    g_status.busy       = true;
    g_failure_result    = WIFI_NOTIFICATION_RESULT_NONE;
    g_response_status   = 0U;
    g_response_success  = false;
    g_response_finished = false;
    g_tls_connected     = false;
    g_connection_failed = false;
    g_close_requested   = false;
    g_deadline_ms = to_ms_since_boot(get_absolute_time()) + DNS_TIMEOUT_MS;
    cyw43_arch_lwip_end();
    return true;
}

static void
service_tls (uint32_t now)
{
    if (gp_https_pcb == NULL && !g_connection_failed)
    {
        if (start_tls_connection())
        {
            g_deadline_ms = now + TLS_TIMEOUT_MS;
        }
    }
    else if (g_connection_failed)
    {
        mark_failure(WIFI_NOTIFICATION_RESULT_TLS);
    }
    else if (g_tls_connected)
    {
        telegram_http_parser_init(&g_http_parser);
        g_http_send_offset   = 0U;
        g_http_queued_length = 0U;
        g_state              = STATE_HTTP_SEND;
        g_deadline_ms        = now + SEND_TIMEOUT_MS;
    }
    else if (deadline_reached(g_deadline_ms))
    {
        mark_failure(WIFI_NOTIFICATION_RESULT_TIMEOUT);
    }
}

static void
service_http_send (uint32_t now)
{
    if (g_connection_failed)
    {
        mark_failure(WIFI_NOTIFICATION_RESULT_HTTP);
    }
    else if (deadline_reached(g_deadline_ms))
    {
        mark_failure(WIFI_NOTIFICATION_RESULT_TIMEOUT);
    }
    else
    {
        const size_t request_length = strlen(g_http_request);
        if (g_http_send_offset >= request_length)
        {
            g_state       = STATE_HTTP_WAIT;
            g_deadline_ms = now + HTTP_TIMEOUT_MS;
            return;
        }
        if (g_http_queued_length == 0U)
        {
            const size_t remaining = request_length - g_http_send_offset;
            g_http_queued_length   = remaining < HTTP_WRITE_CHUNK_CAPACITY
                                         ? remaining
                                         : HTTP_WRITE_CHUNK_CAPACITY;
            const err_t write_result =
                altcp_write(gp_https_pcb, g_http_request + g_http_send_offset,
                            (u16_t) g_http_queued_length, TCP_WRITE_FLAG_COPY);
            if (write_result != ERR_OK)
            {
                g_http_queued_length = 0U;
                if (write_result != ERR_MEM)
                {
                    mark_failure(WIFI_NOTIFICATION_RESULT_HTTP);
                }
            }
        }
        if (g_http_queued_length > 0U)
        {
            const err_t output_result = altcp_output(gp_https_pcb);
            if (output_result == ERR_OK)
            {
                g_http_send_offset += g_http_queued_length;
                g_http_queued_length = 0U;
            }
            else if (output_result != ERR_MEM)
            {
                mark_failure(WIFI_NOTIFICATION_RESULT_HTTP);
            }
        }
    }
}

static void
service_http_wait (void)
{
    if (g_connection_failed)
    {
        mark_failure(WIFI_NOTIFICATION_RESULT_HTTP);
    }
    else if (g_response_finished)
    {
        g_state = STATE_FINISH;
    }
    else if (deadline_reached(g_deadline_ms))
    {
        mark_failure(WIFI_NOTIFICATION_RESULT_TIMEOUT);
    }
}

void
wifi_notification_service (void)
{
    uint32_t now = 0U;
    if (!g_status.stack_ready)
    {
        return;
    }
    now = to_ms_since_boot(get_absolute_time());
    cyw43_arch_lwip_begin();
    g_status.wifi_connected = wifi_link_is_up();
    if (!g_status.wifi_connected)
    {
        if (g_status.busy)
        {
            mark_failure(WIFI_NOTIFICATION_RESULT_WIFI);
        }
        if (deadline_reached(g_next_action_ms))
        {
            const int result = cyw43_arch_wifi_connect_async(
                WIFI_SSID, WIFI_PASSWORD, CYW43_AUTH_WPA2_AES_PSK);
            (void) result;
            g_next_action_ms = now + WIFI_RETRY_INTERVAL_MS;
        }
    }
    else if (g_state == STATE_WIFI_WAIT && deadline_reached(g_next_action_ms))
    {
        if (g_request_queued)
        {
            telegram_http_parser_init(&g_http_parser);
            g_response_status   = 0U;
            g_response_finished = false;
            g_response_success  = false;
            begin_dns_lookup();
        }
        else
        {
            g_next_action_ms = now + WIFI_RETRY_INTERVAL_MS;
        }
    }
    else if (g_state == STATE_DNS_WAIT && deadline_reached(g_deadline_ms))
    {
        /* Keep the context allocated until lwIP returns its one callback. */
        mark_failure(WIFI_NOTIFICATION_RESULT_TIMEOUT);
    }
    else if (g_state == STATE_TLS_WAIT)
    {
        service_tls(now);
    }
    else if (g_state == STATE_HTTP_SEND)
    {
        service_http_send(now);
    }
    else if (g_state == STATE_HTTP_WAIT)
    {
        service_http_wait();
    }
    if (g_close_requested)
    {
        g_state = STATE_FINISH;
    }
    if (g_state == STATE_FINISH)
    {
        finish_request();
    }
    cyw43_arch_lwip_end();
}

void
wifi_notification_get_status (wifi_notification_status_t * status)
{
    if (status != NULL)
    {
        if (!g_status.stack_ready)
        {
            *status = g_status;
            return;
        }
        cyw43_arch_lwip_begin();
        *status = g_status;
        cyw43_arch_lwip_end();
    }
}
