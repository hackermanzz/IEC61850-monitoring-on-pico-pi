/** @file storage.c
 * @brief Stream immutable evidence through copied messages,not shared pointers.
 */
#include "storage.h"
#include <inttypes.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include "tk/tkernel.h"
#include "pico/time.h"
#include "sd_spi.h"
#include "storage_file.h"
#include "storage_record.h"

#define STORAGE_STACK_WORDS   (512u)
#define STORAGE_STACK_PATTERN (0xa5a5a5a5u)
#define STORAGE_QUEUE_COUNT   (2u)
#define STORAGE_DISABLED      (0u)
#define STORAGE_WAITING       (1u)
#define STORAGE_READY         (2u)
#define STORAGE_ERROR         (3u)
#define STORAGE_MAX_RECORD                                                     \
    (STORAGE_RECORD_HEADER + 72u * 4u + 4u * (STORAGE_PACKET_HEADER + 1518u))

_Alignas(8) static uint32_t g_stack[STORAGE_STACK_WORDS];
_Alignas(8) static uint8_t
    g_chunk_bytes[STORAGE_QUEUE_COUNT
                  * (sizeof(INT) + sizeof(storage_chunk_t))];
_Alignas(8) static uint8_t
    g_ack_bytes[2u * (sizeof(INT) + sizeof(storage_ack_t))];
static ID          g_chunks;
static ID          g_acks;
static atomic_uint g_state;
static atomic_uint g_written;
static atomic_uint g_durable;
static atomic_uint g_failed;
static atomic_uint g_file_error;
static atomic_uint g_stack_used;
/* These fields belong only to S3. A queued chunk contains a private copy. */
static uint32_t g_attempted;
static uint32_t g_backpressure;
static uint32_t g_bad_ack;
static uint32_t g_encode_error;
static bool     gb_sending;
static bool     gb_waiting_ack;
static uint32_t g_slot;
static uint32_t g_incident_id;
static uint32_t g_offset;
static uint32_t g_total;
/* These fields belong only to S1. */
static bool          gb_writing;
static bool          gb_ack_pending;
static storage_ack_t g_pending_ack;
static uint32_t      g_writer_offset;
static uint32_t      g_writer_total;
static uint64_t      g_retry_at;

static void storage_task(INT code, void * p_exinf);

bool
storage_init (void)
{
    T_CMBF queue = {0};
    queue.mbfatr = TA_USERBUF;
    queue.maxmsz = sizeof(storage_chunk_t);
    queue.bufsz  = sizeof(g_chunk_bytes);
    queue.bufptr = g_chunk_bytes;
    g_chunks     = tk_cre_mbf(&queue);
    if (0 >= g_chunks)
    {
        return false;
    }
    queue.maxmsz = sizeof(storage_ack_t);
    queue.bufsz  = sizeof(g_ack_bytes);
    queue.bufptr = g_ack_bytes;
    g_acks       = tk_cre_mbf(&queue);
    if (0 >= g_acks)
    {
        (void) tk_del_mbf(g_chunks);
        return false;
    }
    atomic_store(&g_state,
                 sd_spi_configured() ? STORAGE_WAITING : STORAGE_DISABLED);
    return true;
}

bool
storage_start (void)
{
    T_CTSK task = {0};
    ID     id   = 0;
    for (size_t index = 0u; STORAGE_STACK_WORDS > index; index++)
    {
        g_stack[index] = STORAGE_STACK_PATTERN;
    }
    task.tskatr  = TA_HLNG | TA_USERBUF | TA_ASSPRC;
    task.task    = (FP) storage_task;
    task.itskpri = 18;
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
    return true;
}

void
storage_poll (void)
{
    storage_ack_t             ack      = {0};
    storage_chunk_t           chunk    = {0};
    const evidence_record_t * p_record = NULL;
    for (size_t index = 0u; EVIDENCE_SLOTS > index; index++)
    {
        if ((INT) sizeof(ack) == tk_rcv_mbf(g_acks, &ack, TMO_POL))
        {
            if (gb_sending && (gb_waiting_ack || (0u == ack.success))
                && (ack.slot == g_slot) && (ack.incident_id == g_incident_id)
                && (1u >= ack.success))
            {
                if (1u == ack.success)
                {
                    if (evidence_release(ack.slot, ack.incident_id))
                    {
                        g_attempted &= ~(1u << ack.slot);
                    }
                }
                gb_sending     = false;
                gb_waiting_ack = false;
            }
            else
            {
                g_bad_ack++;
            }
        }
    }
    if (STORAGE_READY != atomic_load(&g_state))
    {
        return;
    }
    if (!gb_sending)
    {
        for (uint32_t slot = 0u; EVIDENCE_SLOTS > slot; slot++)
        {
            p_record = evidence_record(slot);
            if ((NULL != p_record) && (0u == (g_attempted & (1u << slot))))
            {
                g_total = storage_record_size(p_record);
                g_attempted |= 1u << slot;
                if (0u == g_total)
                {
                    g_encode_error++;
                }
                else
                {
                    gb_sending    = true;
                    g_slot        = slot;
                    g_incident_id = p_record->incident_id;
                    g_offset      = 0u;
                    break;
                }
            }
        }
    }
    if ((!gb_sending) || gb_waiting_ack)
    {
        return;
    }
    p_record = evidence_record(g_slot);
    if ((NULL == p_record) || (p_record->incident_id != g_incident_id))
    {
        g_encode_error++;
        gb_sending = false;
        return;
    }
    chunk.slot        = g_slot;
    chunk.incident_id = g_incident_id;
    chunk.offset      = g_offset;
    chunk.total       = g_total;
    chunk.length      = (uint16_t) storage_record_read(
        p_record, g_offset, chunk.data, sizeof(chunk.data));
    if (0u == chunk.length)
    {
        g_encode_error++;
        gb_sending = false;
        return;
    }
    if (0u == g_offset)
    {
        chunk.flags |= STORAGE_START;
    }
    if (g_offset + chunk.length == g_total)
    {
        chunk.flags |= STORAGE_END;
    }
    /* Waiting for completion is set BEFORE publication: even a future
     * higher-priority worker cannot acknowledge a record S3 has not marked.
     */
    gb_waiting_ack = (0u != (chunk.flags & STORAGE_END));
    if (E_OK == tk_snd_mbf(g_chunks, &chunk, sizeof(chunk), TMO_POL))
    {
        g_offset += chunk.length;
    }
    else
    {
        gb_waiting_ack = false;
        g_backpressure++;
    }
}

static void
storage_complete (bool success)
{
    if (!success)
    {
        storage_file_abort();
        atomic_fetch_add(&g_failed, 1u);
        atomic_store(&g_file_error, storage_file_error());
        atomic_store(&g_state, STORAGE_ERROR);
        g_retry_at = time_us_64() + 5000000u;
    }
    else
    {
        atomic_fetch_add(&g_durable, 1u);
    }
    g_pending_ack.success = success ? 1u : 0u;
    gb_ack_pending        = true;
    gb_writing            = false;
}

void
storage_worker_step (void)
{
    storage_chunk_t chunk = {0};
    if (gb_ack_pending)
    {
        if (E_OK
            != tk_snd_mbf(g_acks, &g_pending_ack, sizeof(g_pending_ack),
                          TMO_POL))
        {
            return;
        }
        gb_ack_pending = false;
    }
    if (!sd_spi_configured())
    {
        return;
    }
    if (STORAGE_READY != atomic_load(&g_state))
    {
        if (time_us_64() < g_retry_at)
        {
            return;
        }
        if (!storage_file_mount())
        {
            atomic_store(&g_file_error, storage_file_error());
            atomic_store(&g_state, STORAGE_ERROR);
            g_retry_at = time_us_64() + 5000000u;
            return;
        }
        atomic_store(&g_file_error, 0u);
        atomic_store(&g_state, STORAGE_READY);
    }
    if ((INT) sizeof(chunk) != tk_rcv_mbf(g_chunks, &chunk, TMO_POL))
    {
        return;
    }
    if (0u != (chunk.flags & STORAGE_START))
    {
        if (gb_writing)
        {
            storage_complete(false);
            return;
        }
        g_pending_ack.slot        = chunk.slot;
        g_pending_ack.incident_id = chunk.incident_id;
        g_writer_offset           = 0u;
        g_writer_total            = chunk.total;
        gb_writing                = true;
        if ((0u != chunk.offset) || (0u == chunk.total)
            || (STORAGE_MAX_RECORD < chunk.total)
            || (EVIDENCE_SLOTS <= chunk.slot) || (0u == chunk.incident_id)
            || (!storage_file_begin()))
        {
            storage_complete(false);
            return;
        }
    }
    if (!gb_writing)
    {
        return;
    }
    if ((chunk.slot != g_pending_ack.slot)
        || (chunk.incident_id != g_pending_ack.incident_id)
        || (chunk.offset != g_writer_offset) || (chunk.total != g_writer_total)
        || (0u == chunk.length) || (STORAGE_CHUNK_BYTES < chunk.length)
        || (chunk.length > g_writer_total - g_writer_offset)
        || (0u != (chunk.flags & ~(STORAGE_START | STORAGE_END)))
        || (!storage_file_write(chunk.data, chunk.length)))
    {
        storage_complete(false);
        return;
    }
    g_writer_offset += chunk.length;
    atomic_fetch_add(&g_written, chunk.length);
    if (0u != (chunk.flags & STORAGE_END))
    {
        storage_complete((g_writer_offset == g_writer_total)
                         && storage_file_commit());
    }
    else if (g_writer_offset == g_writer_total)
    {
        storage_complete(false);
    }
}

static void
storage_task (INT code, void * p_exinf)
{
    uint32_t untouched = 0u;
    (void) code;
    (void) p_exinf;
    for (;;)
    {
        storage_worker_step();
        untouched = 0u;
        while ((STORAGE_STACK_WORDS > untouched)
               && (STORAGE_STACK_PATTERN == g_stack[untouched]))
        {
            untouched++;
        }
        atomic_store(&g_stack_used,
                     (STORAGE_STACK_WORDS - untouched) * sizeof(uint32_t));
        (void) tk_dly_tsk(10u);
    }
}

void
storage_report (void)
{
    printf("SD state=%u pins=%u durable=%u failed=%u bytes=%u file_error=%u"
           " spi_error=%u stack_used=%u/2048\n",
           atomic_load(&g_state), sd_spi_configured() ? 1u : 0u,
           atomic_load(&g_durable), atomic_load(&g_failed),
           atomic_load(&g_written), atomic_load(&g_file_error),
           (unsigned) sd_spi_error(), atomic_load(&g_stack_used));
    uint32_t timeout_context = sd_spi_timeout_context();
    printf("SD timeouts=%" PRIu32 " last_timeout_phase=%" PRIu32
           " last_timeout_cmd=%" PRIu32 "\n",
           sd_spi_timeout_count(), timeout_context >> 8u,
           timeout_context & 0xffu);
    printf("SD backpressure=%" PRIu32 " bad_ack=%" PRIu32
           " encode_error=%" PRIu32 "\n",
           g_backpressure, g_bad_ack, g_encode_error);
}

/*** end of file ***/
