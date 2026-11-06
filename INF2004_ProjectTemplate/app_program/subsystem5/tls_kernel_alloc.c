#include "../app.h"
#include "notification_port.h"
#include <limits.h>
#include <string.h>

typedef union {
    size_t size;
    max_align_t alignment;
} allocation_header_t;
static size_t bytes_current, bytes_peak;
static uint32_t allocation_failures;

void *monitor_tls_calloc(size_t count, size_t bytes)
{
    if (count == 0 || bytes == 0 || count > INT_MAX / bytes ||
        count * bytes > INT_MAX - sizeof(allocation_header_t)) {
        allocation_failures++;
        return NULL;
    }
    size_t length = count * bytes;
    allocation_header_t *header = Kcalloc(1, sizeof(*header) + length);
    if (header == NULL) { allocation_failures++; return NULL; }
    header->size = length;
    bytes_current += sizeof(*header) + length;
    if (bytes_current > bytes_peak) bytes_peak = bytes_current;
    return header + 1;
}

void monitor_tls_free(void *pointer)
{
    if (pointer != NULL) {
        allocation_header_t *header = (allocation_header_t *)pointer - 1;
        bytes_current -= sizeof(*header) + header->size;
        Kfree(header);
    }
}

void monitor_tls_memory_stats(size_t *current, size_t *peak, uint32_t *failures)
{
    if (current) *current = bytes_current;
    if (peak) *peak = bytes_peak;
    if (failures) *failures = allocation_failures;
}
