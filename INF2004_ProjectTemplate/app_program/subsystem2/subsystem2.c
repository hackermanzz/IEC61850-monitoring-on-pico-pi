#include "subsystem2.h"
#include "capture_frame.h"
EXPORT ID sem_slots;
EXPORT ID mpf_samples;

//! Initialize Semaphore
EXPORT ER subsystem2_init(void)
{
    T_CSEM sem = {0};
    T_CMPF pool = {0};
    sem.sematr = TA_TFIFO;
    sem.isemcnt = sem.maxsem = POOL_COUNT;
    sem_slots = tk_cre_sem(&sem);
    if (sem_slots < E_OK) return sem_slots;
    pool.mpfatr = TA_TFIFO | TA_RNG3;
    pool.mpfcnt = POOL_COUNT;
    pool.blfsz = sizeof(capture_frame_t);
    mpf_samples = tk_cre_mpf(&pool);
    return mpf_samples < E_OK ? mpf_samples : E_OK;
}
EXPORT ER subsystem2_start(void)
{
    ID id = app_start_task_ex(producer_task, MONITOR_CAPTURE_PRIORITY,
                             TP_PRC2, MONITOR_CAPTURE_STACK);
    return id < E_OK ? id : E_OK;
}
