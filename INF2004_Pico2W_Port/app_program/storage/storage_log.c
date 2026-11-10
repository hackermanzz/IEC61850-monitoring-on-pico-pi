/** @file storage_log.c
 * @brief Original on-card IRTLOG/1 companion. No printf, heap or per-task TLS.
 * Keep raw packets/model vectors in BIN; expose investigation facts once here.
 */
#include "storage_log.h"
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "pico/unique_id.h"
#include "storage_hash.h"
#include "../analysis/generated_batch_models.h"
#ifndef PICO_PROGRAM_VERSION_STRING
#define PICO_PROGRAM_VERSION_STRING "host-preview"
#endif
#ifndef STORAGE_MODEL_SHA256
#define STORAGE_MODEL_SHA256 "unavailable"
#endif
static FIL            g_log;
static uint8_t        g_header[132];
static uint8_t        g_identity[132];
static uint8_t        g_buffer[192];
static storage_hash_t g_hash;
static size_t         g_used;
static FRESULT        g_result;
static uint32_t
storage_log_u32 (const uint8_t * p)
{
    return (uint32_t) p[0] | ((uint32_t) p[1] << 8u) | ((uint32_t) p[2] << 16u)
         | ((uint32_t) p[3] << 24u);
}
static uint64_t
storage_log_u64 (const uint8_t * p)
{
    return storage_log_u32(p) | ((uint64_t) storage_log_u32(p + 4u) << 32u);
}
static uint16_t
storage_log_u16 (const uint8_t * p)
{
    return (uint16_t) ((uint16_t) p[0] | ((uint16_t) p[1] << 8u));
}
static void
storage_log_flush (void)
{
    UINT written = 0u;
    if ((g_result == FR_OK) && (g_used > 0u))
    {
        g_result = f_write(&g_log, g_buffer, (UINT) g_used, &written);
        if ((g_result == FR_OK) && (written != g_used))
        {
            g_result = FR_DENIED;
        }
    }
    g_used = 0u;
}
static void
storage_log_char (char c)
{
    if (g_result == FR_OK)
    {
        g_buffer[g_used++] = (uint8_t) c;
        if (g_used == sizeof(g_buffer))
        {
            storage_log_flush();
        }
    }
}
static void
storage_log_text (const char * p)
{
    while (*p != '\0')
    {
        storage_log_char(*p++);
    }
}
static void
storage_log_number (uint64_t value)
{
    char   digits[20];
    size_t n = 0u;
    do
    {
        digits[n++] = (char) ('0' + value % 10u);
        value /= 10u;
    } while (value > 0u);
    while (n > 0u)
    {
        storage_log_char(digits[--n]);
    }
}
static void
storage_log_hex (uint8_t value)
{
    static const char digits[] = "0123456789abcdef";
    storage_log_char(digits[value >> 4u]);
    storage_log_char(digits[value & 15u]);
}
static void
storage_log_float (uint32_t bits)
{
    /* Six significant display digits. Exact IEEE words remain in BIN.
     * Compiler software-float helpers are stateless, unlike libc formatting.
     */
    float value    = 0.0f;
    int   exponent = 0;
    if ((bits & 0x7f800000u) == 0x7f800000u)
    {
        storage_log_text((bits & 0x007fffffu) != 0u
                             ? "NaN"
                             : ((bits >> 31u) != 0u ? "-Inf" : "Inf"));
        return;
    }
    if ((bits & 0x7fffffffu) == 0u)
    {
        storage_log_char('0');
        return;
    }
    if ((bits >> 31u) != 0u)
    {
        storage_log_char('-');
    }
    bits &= 0x7fffffffu;
    memcpy(&value, &bits, sizeof(value));
    while (value >= 10.0f)
    {
        value /= 10.0f;
        exponent++;
    }
    while (value < 1.0f)
    {
        value *= 10.0f;
        exponent--;
    }
    uint32_t number = (uint32_t) (value * 100000.0f + 0.5f);
    if (number >= 1000000u)
    {
        number = 100000u;
        exponent++;
    }
    char digits[6];
    for (unsigned i = 0u; i < 6u; i++)
    {
        digits[5u - i] = (char) ('0' + number % 10u);
        number /= 10u;
    }
    unsigned end = 6u;
    while ((end > 1u) && (digits[end - 1u] == '0'))
    {
        end--;
    }
    if ((exponent >= -3) && (exponent <= 6))
    {
        int point = exponent + 1;
        if (point <= 0)
        {
            storage_log_text("0.");
            for (int i = 0; i < -point; i++)
            {
                storage_log_char('0');
            }
            for (unsigned i = 0u; i < end; i++)
            {
                storage_log_char(digits[i]);
            }
        }
        else
        {
            for (int i = 0; i < point; i++)
            {
                storage_log_char(((unsigned) i < end) ? digits[i] : '0');
            }
            if ((unsigned) point < end)
            {
                storage_log_char('.');
                for (unsigned i = (unsigned) point; i < end; i++)
                {
                    storage_log_char(digits[i]);
                }
            }
        }
    }
    else
    {
        storage_log_char(digits[0]);
        if (end > 1u)
        {
            storage_log_char('.');
            for (unsigned i = 1u; i < end; i++)
            {
                storage_log_char(digits[i]);
            }
        }
        storage_log_char('e');
        storage_log_char(exponent < 0 ? '-' : '+');
        storage_log_number((uint32_t) (exponent < 0 ? -exponent : exponent));
    }
}
static FRESULT
storage_log_read (FIL * p, uint8_t * data, UINT count)
{
    UINT    got    = 0u;
    FRESULT result = f_read(p, data, count, &got);
    return ((result == FR_OK) && (got != count)) ? FR_INT_ERR : result;
}
static void
storage_log_mac (const uint8_t * p)
{
    for (unsigned i = 0u; i < 6u; i++)
    {
        if (i > 0u)
        {
            storage_log_char(':');
        }
        storage_log_hex(p[i]);
    }
}
static void
storage_log_stream (void)
{
    storage_log_text("stream appid=0x");
    storage_log_hex(g_header[3]);
    storage_log_hex(g_header[2]);
    storage_log_text(" src=");
    storage_log_mac(g_header + 28u);
    storage_log_text(" dst=");
    storage_log_mac(g_header + 34u);
    storage_log_text(" id=\"");
    for (unsigned i = 0u; i < g_header[40]; i++)
    {
        uint8_t c = g_header[68u + i];
        if ((c < 0x20u) || (c >= 0x7fu))
        {
            storage_log_text("\\x");
            storage_log_hex(c);
        }
        else
        {
            if ((c == '"') || (c == '\\'))
            {
                storage_log_char('\\');
            }
            storage_log_char((char) c);
        }
    }
    storage_log_text("\"\n");
}
static bool
storage_log_same_identity (void)
{
    return (memcmp(g_header + 2u, g_identity + 2u, 2u) == 0)
        && (memcmp(g_header + 28u, g_identity + 28u, 13u) == 0)
        && (memcmp(g_header + 68u, g_identity + 68u, g_header[40]) == 0);
}
static void
storage_log_reasons (uint32_t mask)
{
    static const char * const names[] = {
        "structure",     "unconfigured_stream", "source_mismatch",
        "configuration", "test_flag",           "commissioning",
        "counter",       "data_without_state",  "timing",
        "capture_gap",   "unsupported"};
    bool any = false;
    for (unsigned i = 0u; i < 11u; i++)
    {
        if ((mask & (1u << i)) != 0u)
        {
            if (any)
            {
                storage_log_char(',');
            }
            storage_log_text(names[i]);
            any = true;
        }
    }
    if ((mask & ~0x7ffu) != 0u)
    {
        if (any)
        {
            storage_log_char(',');
        }
        storage_log_text("unknown_bits");
        any = true;
    }
    if (!any)
    {
        storage_log_text("none");
    }
}
FRESULT
storage_log_create(FIL * p_binary, const char * p_binary_name,
                   const char * p_log_name)
{
    uint8_t  digest[32];
    char     device[17];
    FRESULT  result   = FR_OK;
    UINT     got      = 0u;
    uint32_t total    = (uint32_t) f_size(p_binary);
    uint64_t previous = 0u;
    if ((total < 48u) || (total > 6936u))
    {
        return FR_INT_ERR;
    }
    /* Read/hash the actual completed file, not the producer's old RAM view. */
    storage_hash_init(&g_hash);
    do
    {
        result = f_read(p_binary, g_buffer, sizeof(g_buffer), &got);
        if (result != FR_OK)
        {
            return result;
        }
        storage_hash_update(&g_hash, g_buffer, got);
    } while (got > 0u);
    if (g_hash.bytes != total)
    {
        return FR_INT_ERR;
    }
    storage_hash_finish(&g_hash, digest);
    result = f_lseek(p_binary, 0u);
    if (result == FR_OK)
    {
        result = storage_log_read(p_binary, g_header, 48u);
    }
    if (result != FR_OK)
    {
        return result;
    }
    uint32_t protocol = storage_log_u32(g_header + 20u);
    uint16_t count    = storage_log_u16(g_header + 34u);
    if ((memcmp(g_header, "P2INC001", 8u) != 0)
        || (storage_log_u16(g_header + 8u) != 1u)
        || (storage_log_u16(g_header + 10u) != 48u)
        || (storage_log_u32(g_header + 12u) != total)
        || (storage_log_u16(g_header + 32u) != 4u) || (protocol > 1u)
        || (count != (protocol == 0u ? 52u : 72u)))
    {
        return FR_INT_ERR;
    }
    result = f_open(&g_log, p_log_name, FA_WRITE | FA_CREATE_NEW);
    if (result != FR_OK)
    {
        return result;
    }
    g_result = FR_OK;
    g_used   = 0u;
    pico_get_unique_board_id_string(device, sizeof(device));
    storage_log_text("IRTLOG/1\nevidence=");
    storage_log_text(p_binary_name + 7u);
    storage_log_text(" bytes=");
    storage_log_number(total);
    storage_log_text("\nsha256=");
    for (unsigned i = 0u; i < 32u; i++)
    {
        storage_log_hex(digest[i]);
    }
    storage_log_text("\ndevice=");
    storage_log_text(device);
    storage_log_text(" writer_firmware=");
    storage_log_text(PICO_PROGRAM_VERSION_STRING);
    storage_log_text("\nmodel_source_sha256=");
    storage_log_text(STORAGE_MODEL_SHA256);
    storage_log_text("\nmodel_schema=");
    storage_log_text(PICO_ML_BATCH_SCHEMA_FINGERPRINT);
    storage_log_text("\nincident=");
    storage_log_number(storage_log_u32(g_header + 16u));
    storage_log_text(" id_scope=boot protocol=");
    storage_log_text(protocol == 0u ? "GOOSE" : "SV");
    storage_log_text(" label=");
    storage_log_number(storage_log_u32(g_header + 36u));
    storage_log_text(" verdict=");
    storage_log_text(storage_log_u32(g_header + 36u) != 0u ? "model_anomaly"
                                                           : "normal");
    storage_log_text(" score=");
    storage_log_float(storage_log_u32(g_header + 40u));
    float    threshold      = protocol == 0u ? PICO_ML_BATCH_GOOSE_THRESHOLD
                                             : PICO_ML_BATCH_SV_THRESHOLD;
    uint32_t threshold_bits = 0u;
    memcpy(&threshold_bits, &threshold, sizeof(threshold_bits));
    storage_log_text(" threshold=");
    storage_log_float(threshold_bits);
    storage_log_text(
        "\ntime_basis=boot_uptime_us utc=unavailable incident_us=");
    storage_log_number(storage_log_u64(g_header + 24u));
    storage_log_text("\nrule_mode=shadow mask=0x");
    uint32_t reasons = storage_log_u32(g_header + 44u);
    for (unsigned i = 0u; i < 4u; i++)
    {
        storage_log_hex((uint8_t) (reasons >> (24u - i * 8u)));
    }
    storage_log_text(" findings=");
    storage_log_reasons(reasons);
    storage_log_text("\nframes=4 model_inputs=");
    storage_log_number(count);
    storage_log_text(" exact_packets_and_inputs=BIN "
                     "packet_format=ethernet_no_fcs display_digits=6\n");
    if (protocol == 1u)
    {
        storage_log_text("values=ch0..ch5 units=unrecorded\n");
    }
    else
    {
        storage_log_text("value=first_boolean\n");
    }
    result = f_lseek(p_binary, 48u + (uint32_t) count * 4u);
    for (unsigned i = 0u; (i < 4u) && (result == FR_OK) && (g_result == FR_OK);
         i++)
    {
        result = storage_log_read(p_binary, g_header, sizeof(g_header));
        if (result != FR_OK)
        {
            break;
        }
        uint16_t length = storage_log_u16(g_header);
        uint64_t now    = storage_log_u64(g_header + 8u);
        if ((length == 0u) || (length > 1518u) || (g_header[40] > 64u)
            || (g_header[41] != (protocol == 0u ? 1u : 2u))
            || (storage_log_u16(g_header + 42u) != 0u)
            || (f_tell(p_binary) > total) || (length > total - f_tell(p_binary))
            || ((i > 0u) && (now < previous)))
        {
            result = FR_INT_ERR;
            break;
        }
        if ((i == 0u) || !storage_log_same_identity())
        {
            storage_log_stream();
            memcpy(g_identity, g_header, sizeof(g_identity));
        }
        storage_log_text("packet seq=");
        storage_log_number(storage_log_u32(g_header + 4u));
        storage_log_text(" t_us=");
        storage_log_number(now);
        storage_log_text(" dt_us=");
        if (i == 0u)
        {
            storage_log_char('-');
        }
        else
        {
            storage_log_number(now - previous);
        }
        storage_log_text(" len=");
        storage_log_number(length);
        storage_log_text(protocol == 0u ? " stNum=" : " smpCnt=");
        storage_log_number(storage_log_u32(g_header + 16u));
        if (protocol == 0u)
        {
            storage_log_text(" sqNum=");
            storage_log_number(storage_log_u32(g_header + 20u));
            storage_log_text(" value=");
            storage_log_text(storage_log_u32(g_header + 44u) != 0u ? "true"
                                                                   : "false");
        }
        else
        {
            storage_log_text(" values=");
            for (unsigned j = 0u; j < 6u; j++)
            {
                if (j > 0u)
                {
                    storage_log_char(',');
                }
                storage_log_float(storage_log_u32(g_header + 44u + j * 4u));
            }
        }
        storage_log_char('\n');
        previous = now;
        result   = f_lseek(p_binary, f_tell(p_binary) + length);
    }
    if ((result == FR_OK) && (f_tell(p_binary) != total))
    {
        result = FR_INT_ERR;
    }
    if ((result == FR_OK) && (g_result == FR_OK))
    {
        storage_log_text("END\n");
        storage_log_flush();
    }
    if (result == FR_OK)
    {
        result = g_result;
    }
    if (result == FR_OK)
    {
        result = f_sync(&g_log);
    }
    FRESULT closed = f_close(&g_log);
    if (result == FR_OK)
    {
        result = closed;
    }
    return result;
}
/*** end of file ***/
