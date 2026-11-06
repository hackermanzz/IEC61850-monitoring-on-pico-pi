#include "subsystem5.h"
#include "../monitor_stacks.h"
#include "notification_port.h"
#include "../bounded_text.h"
#include "../subsystem4/subsystem4.h"
#include "../monitor_time.h"
/* Copied notification records are independent of capture/evidence ownership. */
typedef struct {
    uint32_t id_low, protocol, stream_key, appid, retained;
} notice_t;
EXPORT ID mbf_notifications;
void monitor_notification_report(const monitor_network_stats_t *status)
{
    monitor_status_message_t message = {0};
    message.source = 5;
    message.generated_us = monitor_time_us();
    message.data.network = *status;
    (void)subsystem4_publish(&message);
}
int monitor_notification_take(char *text, size_t capacity)
{
    notice_t notice;
    if (mbf_notifications <= 0 || text == NULL || capacity == 0) return 0;
    INT len = tk_rcv_mbf(mbf_notifications, &notice, TMO_POL);
    if (len != sizeof(notice)) return 0;
    monitor_text_t out = monitor_text_begin(text, capacity);
    monitor_text_string(&out, "IEC61850 incident ");
    monitor_text_u32(&out, notice.id_low);
    monitor_text_string(&out, notice.protocol == 0 ? ": GOOSE APPID=" : ": SV APPID=");
    monitor_text_u32(&out, notice.appid);
    monitor_text_string(&out, " stream=");
    monitor_text_u32(&out, notice.stream_key);
    monitor_text_string(&out, " evidence=");
    monitor_text_u32(&out, notice.retained);
    return out.ok ? (int)out.length : 0;
}
#if !MONITOR_TELEGRAM
void subsystem5_console_poll(INT timeout)
{
    notice_t notice;
    INT len = tk_rcv_mbf(mbf_notifications, &notice, timeout);
    if (len == sizeof(notice)) {
        tm_printf((UB *)"incident: id=%u protocol=%s appid=%u key=%u evidence=%u notification_transport=disabled\n",
            notice.id_low, notice.protocol == 0 ? "GOOSE" : "SV", notice.appid,
            notice.stream_key, notice.retained);
    } else if (len != E_TMOUT) CHECK(len, "notification receive");
}
#if !MONITOR_STORAGE
static void notification_task(INT stacd, void *exinf)
{
    (void)stacd; (void)exinf;
    for (;;) {
        MONITOR_STACK_REPORT(9);
        subsystem5_console_poll(TMO_FEVR);
    }
}
#endif
#endif
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
EXPORT ER subsystem5_start(void)
{
    tid_led = app_start_task_ex(led_task, MONITOR_ALARM_PRIORITY, TP_PRC1, MONITOR_ALARM_STACK);
    if (tid_led < E_OK) return tid_led;
#if !MONITOR_TELEGRAM && !MONITOR_STORAGE
    ID id = app_start_task_ex(notification_task, 18, TP_PRC1, MONITOR_LOG_STACK);
    return id < E_OK ? id : E_OK;
#else
    /* S1 owns SD/console polling, or the radio owner consumes TLS notices. */
    return E_OK;
#endif
}
EXPORT ER subsystem5_notify(const analyzer_result_t *r,
                              const monitor_incident_outcome_t *outcome)
{
    notice_t notice = {(uint32_t)outcome->id, r->protocol, r->stream_key,
                      r->appid, outcome->retained};
    return tk_snd_mbf(mbf_notifications, &notice, sizeof(notice), TMO_POL);
}
