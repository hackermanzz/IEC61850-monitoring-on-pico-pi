#ifndef SUBSYSTEM3_H
#define SUBSYSTEM3_H
#include "../app.h"
#include "../monitor_status.h"
#define S3_BATCH_SIZE 5
IMPORT ID mbx_samples;
IMPORT ID mtx_stats;
typedef monitor_analysis_stats_t APP_STATS;
IMPORT APP_STATS app_stats;
IMPORT void consumer_task(INT stacd, void *exinf);
#endif
