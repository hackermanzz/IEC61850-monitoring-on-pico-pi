#ifndef TELEGRAM_MOCK_API_H
#define TELEGRAM_MOCK_API_H

#include <stdbool.h>
#include <stdint.h>

extern bool     g_mock_link_up;
extern bool     g_mock_tls_new_fails;
extern bool     g_mock_dns_pending;
extern int      g_mock_cyw43_init_result;
extern unsigned g_mock_connect_attempts;
extern unsigned g_mock_dns_calls;
extern unsigned g_mock_tls_config_create_calls;
extern unsigned g_mock_tls_new_calls;
extern unsigned g_mock_lock_depth;
extern unsigned g_mock_lock_violations;
extern unsigned g_mock_write_mem_failures;
extern unsigned g_mock_output_mem_failures;
extern unsigned g_mock_largest_write;
extern unsigned g_mock_write_calls;
extern unsigned g_mock_output_calls;

void telegram_mock_reset (void);
void telegram_mock_receive (const char * response);
void telegram_mock_receive_fragmented (const char * response);
void telegram_mock_receive_chain (const char * response);
void telegram_mock_dns_resolve (unsigned call_index, uint32_t address_value);

#endif
