#ifndef SUBSYSTEM2_H
#define SUBSYSTEM2_H
#include "../app.h"
#include "../monitor_config.h"
#define POOL_COUNT MONITOR_FRAME_BLOCKS
#define S2_PERIOD_MS 300
IMPORT ID sem_slots;
IMPORT ID mpf_samples;
IMPORT void producer_task(INT stacd, void *exinf);
#endif
