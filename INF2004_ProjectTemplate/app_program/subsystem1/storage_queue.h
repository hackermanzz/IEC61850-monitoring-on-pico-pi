#ifndef MONITOR_STORAGE_QUEUE_H
#define MONITOR_STORAGE_QUEUE_H
#include "../app.h"
#include "incident_record.h"
typedef struct { uint64_t incident_id; uint32_t slot; } monitor_storage_ack_t;
IMPORT ID mbf_storage, mbf_storage_ack;
ER monitor_storage_init(void);
ER monitor_storage_submit(const analyzer_result_t *result,
                          const monitor_incident_outcome_t *outcome);
/* S3 services bounded ACKs between frames; SD task never accesses its store. */
void monitor_storage_service_acks(void);
void monitor_storage_poll(void);
#endif
