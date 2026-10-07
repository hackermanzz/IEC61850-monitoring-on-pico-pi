#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "mock_api.h"
#include "pico/cyw43_arch.h"
#include "pico/stdlib.h"
#include "lwip/altcp.h"
#include "lwip/altcp_tls.h"
#include "lwip/dns.h"
#include "wifi_notification.h"

static absolute_time_t         g_mock_now;
static bool                    g_mock_no_ip;
static struct altcp_pcb        g_mock_pcb;
static struct altcp_tls_config g_mock_tls_config;
static unsigned                g_mock_altcp_close_result;
static dns_found_callback_t    g_mock_dns_callbacks[8];
static void *                  g_mock_dns_arguments[8];

bool     g_mock_link_up;
bool     g_mock_tls_new_fails;
bool     g_mock_dns_pending;
int      g_mock_cyw43_init_result;
unsigned g_mock_connect_attempts;
unsigned g_mock_dns_calls;
unsigned g_mock_tls_config_create_calls;
unsigned g_mock_tls_new_calls;
unsigned g_mock_lock_depth;
unsigned g_mock_lock_violations;
unsigned g_mock_write_mem_failures;
unsigned g_mock_output_mem_failures;
unsigned g_mock_largest_write;
unsigned g_mock_write_calls;
unsigned g_mock_output_calls;
cyw43_t  cyw43_state;

void
telegram_mock_reset (void)
{
    memset(&g_mock_pcb, 0, sizeof(g_mock_pcb));
    memset(&g_mock_tls_config, 0, sizeof(g_mock_tls_config));
    memset(g_mock_dns_callbacks, 0, sizeof(g_mock_dns_callbacks));
    memset(g_mock_dns_arguments, 0, sizeof(g_mock_dns_arguments));
    g_mock_link_up                 = false;
    g_mock_no_ip                   = false;
    g_mock_tls_new_fails           = false;
    g_mock_dns_pending             = false;
    g_mock_cyw43_init_result       = 0;
    g_mock_connect_attempts        = 0U;
    g_mock_dns_calls               = 0U;
    g_mock_tls_config_create_calls = 0U;
    g_mock_tls_new_calls           = 0U;
    g_mock_lock_depth              = 0U;
    g_mock_lock_violations         = 0U;
    g_mock_write_mem_failures      = 0U;
    g_mock_output_mem_failures     = 0U;
    g_mock_largest_write           = 0U;
    g_mock_write_calls             = 0U;
    g_mock_output_calls            = 0U;
    g_mock_altcp_close_result      = ERR_OK;
}

absolute_time_t
get_absolute_time (void)
{
    return g_mock_now;
}

uint32_t
to_ms_since_boot (absolute_time_t time)
{
    return (uint32_t) time;
}

int
cyw43_arch_init (void)
{
    return g_mock_cyw43_init_result;
}

void
cyw43_arch_enable_sta_mode (void)
{
}

int
cyw43_arch_wifi_connect_async (const char * ssid, const char * password,
                               unsigned int auth)
{
    (void) ssid;
    (void) password;
    (void) auth;
    g_mock_connect_attempts++;
    return ERR_OK;
}

int
cyw43_wifi_link_status (cyw43_t * state, unsigned int interface)
{
    (void) state;
    (void) interface;
    return g_mock_link_up ? CYW43_LINK_JOIN : CYW43_LINK_DOWN;
}

int
cyw43_tcpip_link_status (cyw43_t * state, unsigned int interface)
{
    if (cyw43_wifi_link_status(state, interface) != CYW43_LINK_JOIN)
    {
        return CYW43_LINK_DOWN;
    }
    return g_mock_no_ip ? CYW43_LINK_NOIP : CYW43_LINK_UP;
}

void
cyw43_arch_lwip_begin (void)
{
    g_mock_lock_depth++;
}

void
cyw43_arch_lwip_end (void)
{
    if (g_mock_lock_depth == 0U)
    {
        g_mock_lock_violations++;
    }
    else
    {
        g_mock_lock_depth--;
    }
}

err_t
dns_gethostbyname (const char * name, ip_addr_t * address,
                   dns_found_callback_t callback, void * argument)
{
    (void) name;
    if (g_mock_dns_pending)
    {
        const unsigned call_index = g_mock_dns_calls;
        assert(call_index <
               sizeof(g_mock_dns_callbacks) / sizeof(g_mock_dns_callbacks[0]));
        g_mock_dns_callbacks[call_index] = callback;
        g_mock_dns_arguments[call_index] = argument;
        g_mock_dns_calls++;
        return ERR_INPROGRESS;
    }
    g_mock_dns_calls++;
    address->value = 1U;
    return ERR_OK;
}

struct altcp_tls_config *
altcp_tls_create_config_client (const uint8_t * cert, size_t cert_length)
{
    (void) cert;
    (void) cert_length;
    g_mock_tls_config_create_calls++;
    return &g_mock_tls_config;
}

struct altcp_pcb *
altcp_tls_new (struct altcp_tls_config * config, unsigned char ip_type)
{
    (void) config;
    (void) ip_type;
    g_mock_tls_new_calls++;
    return g_mock_tls_new_fails ? NULL : &g_mock_pcb;
}

void
telegram_mock_dns_resolve (unsigned call_index, uint32_t address_value)
{
    ip_addr_t resolved_address;
    assert(call_index < g_mock_dns_calls);
    assert(g_mock_dns_callbacks[call_index] != NULL);
    resolved_address.value = address_value;
    cyw43_arch_lwip_begin();
    g_mock_dns_callbacks[call_index]("api.telegram.org", &resolved_address,
                                     g_mock_dns_arguments[call_index]);
    cyw43_arch_lwip_end();
    g_mock_dns_callbacks[call_index] = NULL;
    g_mock_dns_arguments[call_index] = NULL;
}

void *
altcp_tls_context (struct altcp_pcb * pcb)
{
    return pcb;
}

int
mbedtls_ssl_set_hostname (void * context, const char * hostname)
{
    (void) context;
    return strcmp(hostname, "api.telegram.org") == 0 ? 0 : -1;
}

void
altcp_arg (struct altcp_pcb * pcb, void * argument)
{
    pcb->argument = argument;
}

void
altcp_err (struct altcp_pcb * pcb, altcp_err_fn callback)
{
    pcb->error_callback = callback;
}

void
altcp_recv (struct altcp_pcb * pcb, altcp_recv_fn callback)
{
    pcb->receive_callback = callback;
}

err_t
altcp_connect (struct altcp_pcb * pcb, const ip_addr_t * address, uint16_t port,
               altcp_connected_fn callback)
{
    (void) address;
    (void) port;
    pcb->connected_callback = callback;
    return callback(pcb->argument, pcb, ERR_OK);
}

err_t
altcp_write (struct altcp_pcb * pcb, const void * data, u16_t length,
             uint8_t flags)
{
    size_t existing_length = strlen(pcb->request);
    (void) flags;
    g_mock_write_calls++;
    if (length > g_mock_largest_write)
    {
        g_mock_largest_write = length;
    }
    if (g_mock_write_mem_failures > 0U)
    {
        g_mock_write_mem_failures--;
        return ERR_MEM;
    }
    if (existing_length + length >= sizeof(pcb->request))
    {
        return ERR_MEM;
    }
    memcpy(pcb->request + existing_length, data, length);
    pcb->request[existing_length + length] = '\0';
    return ERR_OK;
}

err_t
altcp_output (struct altcp_pcb * pcb)
{
    (void) pcb;
    g_mock_output_calls++;
    if (g_mock_output_mem_failures > 0U)
    {
        g_mock_output_mem_failures--;
        return ERR_MEM;
    }
    return ERR_OK;
}

void
altcp_recved (struct altcp_pcb * pcb, uint16_t length)
{
    (void) pcb;
    (void) length;
}

err_t
altcp_close (struct altcp_pcb * pcb)
{
    (void) pcb;
    return (err_t) g_mock_altcp_close_result;
}

void
altcp_abort (struct altcp_pcb * pcb)
{
    (void) pcb;
}

uint16_t
pbuf_free (struct pbuf * buffer)
{
    struct pbuf * next = NULL;
    while (buffer != NULL)
    {
        next   = buffer->next;
        buffer = next;
    }
    return 0U;
}

static void
dispatch_piece (const char * data, size_t length)
{
    struct pbuf buffer;
    buffer.payload = (void *) data;
    buffer.len     = (uint16_t) length;
    buffer.tot_len = (uint16_t) length;
    buffer.next    = NULL;
    cyw43_arch_lwip_begin();
    (void) g_mock_pcb.receive_callback(g_mock_pcb.argument, &g_mock_pcb,
                                       &buffer, ERR_OK);
    cyw43_arch_lwip_end();
}

void
telegram_mock_receive_fragmented (const char * response)
{
    size_t       index  = 0U;
    const size_t length = strlen(response);
    while (index < length)
    {
        const size_t piece_length = (index % 11U) + 1U;
        const size_t remaining    = length - index;
        const size_t count =
            piece_length < remaining ? piece_length : remaining;
        dispatch_piece(response + index, count);
        index += count;
    }
}

void
telegram_mock_receive (const char * response)
{
    dispatch_piece(response, strlen(response));
}

void
telegram_mock_receive_chain (const char * response)
{
    struct pbuf  buffers[8];
    size_t       offset = 0U;
    size_t       index  = 0U;
    const size_t length = strlen(response);
    assert(length <= 8U * 16U);
    while (offset < length)
    {
        const size_t remaining = length - offset;
        const size_t count     = remaining < 16U ? remaining : 16U;
        buffers[index].payload = (void *) (response + offset);
        buffers[index].len     = (uint16_t) count;
        buffers[index].tot_len = (uint16_t) remaining;
        buffers[index].next =
            offset + count < length ? &buffers[index + 1U] : NULL;
        offset += count;
        index++;
    }
    cyw43_arch_lwip_begin();
    (void) g_mock_pcb.receive_callback(g_mock_pcb.argument, &g_mock_pcb,
                                       &buffers[0], ERR_OK);
    cyw43_arch_lwip_end();
}

static void
drive_http_send (void)
{
    unsigned count = 0U;
    while (count < 16U)
    {
        wifi_notification_service();
        count++;
    }
}

static void
test_failed_init_and_association (void)
{
    wifi_notification_status_t status;
    telegram_mock_reset();
    g_mock_now               = 0U;
    g_mock_cyw43_init_result = -1;
    assert(!wifi_notification_init());
    wifi_notification_get_status(&status);
    assert(!status.stack_ready);
    assert(g_mock_lock_depth == 0U);
    g_mock_cyw43_init_result = 0;
    assert(wifi_notification_init());
    wifi_notification_service();
    assert(g_mock_connect_attempts == 1U);
    g_mock_now = 9999U;
    wifi_notification_service();
    assert(g_mock_connect_attempts == 1U);
    g_mock_now = 10000U;
    wifi_notification_service();
    assert(g_mock_connect_attempts == 2U);
    wifi_notification_get_status(&status);
    assert(status.stack_ready && !status.wifi_connected);

    /* A joined radio must wait for DHCP before accepting HTTPS requests. */
    g_mock_link_up = true;
    g_mock_no_ip   = true;
    g_mock_now     = 10001U;
    assert(cyw43_wifi_link_status(&cyw43_state, CYW43_ITF_STA) ==
           CYW43_LINK_JOIN);
    wifi_notification_service();
    wifi_notification_get_status(&status);
    assert(!status.wifi_connected);
    assert(!wifi_notification_submit("waiting for DHCP"));
    assert(g_mock_dns_calls == 0U);

    g_mock_no_ip = false;
    wifi_notification_service();
    wifi_notification_get_status(&status);
    assert(status.wifi_connected);
    assert(g_mock_connect_attempts == 2U);
}

static void
test_lifecycle_and_large_message (void)
{
    char message[WIFI_NOTIFICATION_MESSAGE_CAPACITY];
    char too_long[WIFI_NOTIFICATION_MESSAGE_CAPACITY + 1U];
    char response[128];
    wifi_notification_status_t status;
    telegram_mock_reset();
    g_mock_now = 20000U;
    assert(wifi_notification_init());
    memset(message, '%', sizeof(message) - 1U);
    message[sizeof(message) - 1U] = '\0';
    g_mock_link_up                = true;
    assert(!wifi_notification_submit(""));
    memset(too_long, 'x', sizeof(too_long) - 1U);
    too_long[sizeof(too_long) - 1U] = '\0';
    assert(!wifi_notification_submit(too_long));
    assert(wifi_notification_submit(message));
    assert(!wifi_notification_submit("busy"));
    g_mock_write_mem_failures  = 1U;
    g_mock_output_mem_failures = 1U;
    drive_http_send();
    assert(g_mock_write_calls >= 4U);
    assert(g_mock_output_calls >= 4U);
    assert(g_mock_largest_write <= 1024U);
    assert(strstr(g_mock_pcb.request, "text=%25%25") != NULL);
    snprintf(response, sizeof(response),
             "HTTP/1.1 200 OK\r\nContent-Length: 39\r\n\r\n"
             "{\"ok\":true,\"result\":{\"message_id\":123}}");
    telegram_mock_receive_chain(response);
    wifi_notification_service();
    wifi_notification_get_status(&status);
    assert(status.succeeded == 1U && status.failed == 0U);
    assert(g_mock_lock_depth == 0U && g_mock_lock_violations == 0U);
    g_mock_now++;
    assert(wifi_notification_submit("reject trailing bytes"));
    drive_http_send();
    telegram_mock_receive_chain("HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n"
                                "{\"ok\":true}X");
    wifi_notification_service();
    wifi_notification_get_status(&status);
    assert(status.succeeded == 1U && status.failed == 1U);
}

static void
test_tls_failure_retry_and_api_failure (void)
{
    wifi_notification_status_t status;
    telegram_mock_reset();
    g_mock_now = 20002U;
    assert(wifi_notification_init());
    g_mock_link_up       = true;
    g_mock_tls_new_fails = true;
    assert(wifi_notification_submit("failure"));
    wifi_notification_service();
    wifi_notification_service();
    wifi_notification_get_status(&status);
    assert(status.failed == 2U &&
           status.last_result == WIFI_NOTIFICATION_RESULT_TLS);
    g_mock_tls_new_fails = false;
    g_mock_now++;
    assert(wifi_notification_submit("retry"));
    drive_http_send();
    telegram_mock_receive("HTTP/1.1 200 OK\r\nContent-Length: 18\r\n\r\n"
                          "{\"ok\":false,\"x\":0}");
    wifi_notification_service();
    wifi_notification_get_status(&status);
    assert(status.failed == 3U &&
           status.last_result == WIFI_NOTIFICATION_RESULT_API);
}

static void
test_dns_timeout_late_callback_and_tls_reuse (void)
{
    wifi_notification_status_t status;
    unsigned                   failed_before          = 0U;
    unsigned                   config_creates_before  = 0U;
    unsigned                   tls_connections_before = 0U;
    unsigned                   dns_calls_before       = 0U;

    telegram_mock_reset();
    g_mock_now = 40000U;
    assert(wifi_notification_init());
    g_mock_link_up     = true;
    g_mock_dns_pending = true;
    wifi_notification_get_status(&status);
    failed_before = status.failed;
    assert(wifi_notification_submit("request A"));
    wifi_notification_service();
    assert(g_mock_dns_calls == 1U);

    g_mock_now += 10000U;
    wifi_notification_service();
    wifi_notification_get_status(&status);
    assert(!status.busy && status.failed == failed_before + 1U);
    assert(status.last_result == WIFI_NOTIFICATION_RESULT_TIMEOUT);

    assert(wifi_notification_submit("request B"));
    g_mock_now++;
    wifi_notification_service();
    assert(g_mock_dns_calls == 2U);
    tls_connections_before = g_mock_tls_new_calls;

    telegram_mock_dns_resolve(0U, 101U);
    wifi_notification_get_status(&status);
    assert(status.busy && status.failed == failed_before + 1U);
    assert(g_mock_tls_new_calls == tls_connections_before);

    telegram_mock_dns_resolve(1U, 202U);
    config_creates_before = g_mock_tls_config_create_calls;
    wifi_notification_service();
    assert(g_mock_tls_new_calls == tls_connections_before + 1U);
    assert(g_mock_tls_config_create_calls == config_creates_before);
    wifi_notification_service();
    drive_http_send();
    telegram_mock_receive("HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n"
                          "{\"ok\":true}");
    wifi_notification_service();
    wifi_notification_get_status(&status);
    assert(!status.busy && status.succeeded == 2U);

    g_mock_dns_pending = false;
    dns_calls_before   = g_mock_dns_calls;
    assert(wifi_notification_submit("request C"));
    g_mock_now++;
    wifi_notification_service();
    assert(g_mock_dns_calls == dns_calls_before + 1U);
    wifi_notification_service();
    assert(g_mock_tls_new_calls == tls_connections_before + 2U);
    assert(g_mock_tls_config_create_calls == config_creates_before);
    wifi_notification_service();
    drive_http_send();
    telegram_mock_receive("HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n"
                          "{\"ok\":true}");
    wifi_notification_service();
    wifi_notification_get_status(&status);
    assert(!status.busy && status.succeeded == 3U);
}

int
main (void)
{
    test_failed_init_and_association();
    test_lifecycle_and_large_message();
    test_tls_failure_retry_and_api_failure();
    test_dns_timeout_late_callback_and_tls_reuse();
    puts("Wi-Fi notification host tests passed");
    return 0;
}
