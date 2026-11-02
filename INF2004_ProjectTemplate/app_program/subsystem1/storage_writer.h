#ifndef MONITOR_STORAGE_WRITER_H
#define MONITOR_STORAGE_WRITER_H
#include "incident_record.h"

typedef struct {
    uint32_t enabled, received, written, packets, failed, dropped;
    uint32_t files, bytes, last_result, retries, ack_dropped, quota_reached;
} monitor_storage_stats_t;

void monitor_storage_writer_reset(void);
void monitor_storage_writer_poll(uint64_t now_us);
void monitor_storage_writer_stats(monitor_storage_stats_t *out);
/* Kernel queue adapters, called only by the low-priority S1 storage owner. */
int monitor_storage_take_record(monitor_incident_record_t *out);
bool monitor_storage_exported(uint32_t slot, uint64_t incident_id);
#endif
