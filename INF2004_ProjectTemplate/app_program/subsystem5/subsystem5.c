#include "subsystem5.h"
#include "../monitor_stacks.h"
#include "notification_port.h"
#include "../bounded_text.h"
#include "../monitor_time.h"
/* Copied notification records are independent of capture/evidence ownership. */
typedef struct {
    uint32_t id_low, protocol, stream_key, appid, retained;
} notice_t;
EXPORT ID mbf_notifications;

EXPORT ID tid_led, flg_alarm;
EXPORT ER subsystem5_alarm(void) { return tk_set_flg(flg_alarm, 1); }
EXPORT ER subsystem5_init(void)
{
    T_CFLG flag = {0};
    flag.flgatr = TA_TFIFO | TA_WSGL;
    flg_alarm = tk_cre_flg(&flag);
    if (flg_alarm < E_OK) return flg_alarm;
    T_CMBF buffer = {0};
    buffer.mbfatr = TA_TFIFO;
    buffer.maxmsz = sizeof(notice_t);
    buffer.bufsz = S5_NOTICE_QUEUE_DEPTH * (sizeof(notice_t) + 4);
    mbf_notifications = tk_cre_mbf(&buffer);
    if (mbf_notifications < E_OK) return mbf_notifications;
    return E_OK;
}