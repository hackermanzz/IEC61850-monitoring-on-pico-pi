/** @file tls_arena.h
 * @brief Fixed radio-owner-only TLS allocator; no kernel/libc heap borrowing.
 */
#ifndef TLS_ARENA_H
#define TLS_ARENA_H
#include <stddef.h>
#include <stdint.h>
#define TLS_ARENA_BYTES (96u * 1024u)
void * monitor_tls_calloc(size_t count, size_t bytes);
void   monitor_tls_free(void * p_memory);
void   monitor_tls_memory_stats(size_t * p_current, size_t * p_peak,
                                uint32_t * p_failures);
#endif

/*** end of file ***/
