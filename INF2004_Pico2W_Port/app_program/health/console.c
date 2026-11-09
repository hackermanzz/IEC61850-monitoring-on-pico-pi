/** @file console.c
 * @brief A low-priority Core0 owner drains complete lines without printf.
 */
#include "console.h"
#include <stdatomic.h>
#include <stdio.h>
#include <inttypes.h>
#include "pico/stdio/driver.h"
#include "pico/stdio_usb.h"
#include "tk/tkernel.h"
#include "tusb.h"
#include "console_queue.h"

#define CONSOLE_STACK_WORDS   (384u)
#define CONSOLE_STACK_PATTERN (0xa5a5a5a5u)
#define CONSOLE_USB_CHUNK     (64u)

static console_queue_t g_queue;
_Alignas(8) static uint32_t g_stack[CONSOLE_STACK_WORDS];
static atomic_uint g_stack_used;

static void           console_out(const char * p_text, int length);
static void           console_task(INT code, void * p_exinf);
static stdio_driver_t g_driver = {.out_chars = console_out};

static void
console_out (const char * p_text, int length)
{
    if (0 < length)
    {
        console_queue_write(&g_queue, p_text, (size_t) length);
    }
}

bool
console_start (void)
{
    T_CTSK task = {0};
    ID     id   = 0;
    console_queue_init(&g_queue);
    for (uint32_t index = 0u; CONSOLE_STACK_WORDS > index; index++)
    {
        g_stack[index] = CONSOLE_STACK_PATTERN;
    }
    task.tskatr  = TA_HLNG | TA_USERBUF | TA_ASSPRC;
    task.task    = (FP) console_task;
    task.itskpri = 8;
    task.stksz   = sizeof(g_stack);
    task.bufptr  = g_stack;
    task.assprc  = TP_PRC1;
    id           = tk_cre_tsk(&task);
    if (0 >= id)
    {
        return false;
    }
    if (E_OK != tk_sta_tsk(id, 0))
    {
        (void) tk_del_tsk(id);
        return false;
    }
    /* The consumer remains the only formatter/libc-state owner. The new task
     * calls only the original SDK USB backend, never printf or stdio_flush.
     * Disable automatic CRLF because the line queue supplies exactly one pair.
     */
    stdio_set_driver_enabled(&stdio_usb, false);
    stdio_set_translate_crlf(&g_driver, false);
    stdio_set_driver_enabled(&g_driver, true);
    return true;
}

void
console_service_step (console_stream_t * p_stream)
{
    size_t chunk = 0u;
    if (0u == p_stream->length)
    {
        p_stream->length = console_queue_peek(&g_queue, p_stream->line,
                                              sizeof(p_stream->line));
        p_stream->offset = 0u;
    }
    chunk = p_stream->length - p_stream->offset;
    if (CONSOLE_USB_CHUNK < chunk)
    {
        chunk = CONSOLE_USB_CHUNK;
    }
    /* Only this task writes the original USB backend. Its IRQ only drains
     * TX, so space cannot decrease while connected. Each SDK call fits in
     * full. The SDK retains USB/TinyUSB locking; do not bypass its backend.
     */
    if ((0u < chunk) && stdio_usb_connected()
        && (tud_cdc_write_available() >= chunk))
    {
        stdio_usb.out_chars(&p_stream->line[p_stream->offset], (int) chunk);
        p_stream->offset += chunk;
        if (p_stream->offset == p_stream->length)
        {
            console_queue_consume(&g_queue, p_stream->length);
            p_stream->length = 0u;
        }
    }
}

static void
console_task (INT code, void * p_exinf)
{
    console_stream_t stream    = {0};
    uint32_t         untouched = 0u;
    (void) code;
    (void) p_exinf;
    for (;;)
    {
        console_service_step(&stream);
        untouched = 0u;
        while ((CONSOLE_STACK_WORDS > untouched)
               && (CONSOLE_STACK_PATTERN == g_stack[untouched]))
        {
            untouched++;
        }
        atomic_store(&g_stack_used,
                     (CONSOLE_STACK_WORDS - untouched) * sizeof(uint32_t));
        /* One bounded USB chunk then yield, even with permanently full logs.
         * This diagnostic task is below alarm/supervisor/analysis priority.
         */
        (void) tk_dly_tsk(1u);
    }
}

void
console_report (void)
{
    printf("LOG queued_bytes=%" PRIu32 " dropped_lines=%" PRIu32
           " stack_used=%u/1536\n",
           console_queue_pending(&g_queue), console_queue_dropped(&g_queue),
           atomic_load(&g_stack_used));
}

/*** end of file ***/
