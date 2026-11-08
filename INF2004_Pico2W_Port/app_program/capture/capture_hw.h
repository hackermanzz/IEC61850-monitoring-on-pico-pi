/** @file capture_hw.h
 * @brief Core 1-only PIO/DMA ownership and bounded raw sample storage.
 */
#ifndef CAPTURE_HW_H
#define CAPTURE_HW_H

#include <stdbool.h> /* Initialization/take results. */
#include <stddef.h>  /* Word counts. */
#include <stdint.h>  /* Samples and timestamps. */

#define CAPTURE_RAW_WORDS 7000u

/** @brief Count completed words from the stable post-stop DMA write pointer.
 * @note Reject foreign/misaligned pointers and preserve failed output.
 */
static inline bool
capture_hw_dma_count (uintptr_t base, uintptr_t write_address, size_t * p_count)
{
    bool b_valid =
        (NULL != p_count) && (base <= write_address)
        && (CAPTURE_RAW_WORDS * sizeof(uint32_t) >= write_address - base)
        && (0u == (write_address - base) % sizeof(uint32_t));

    if (b_valid)
    {
        *p_count = (write_address - base) / sizeof(uint32_t);
    }
    return b_valid;
}

typedef struct
{
    const uint32_t * p_words;
    size_t           word_count;
    uint64_t         timestamp_us;
    uint32_t         sequence;
    uint32_t         slot;
    bool             b_damaged;
    uint32_t         end_pc;
    uint32_t         pio_irq;
    uint32_t         irq_enable;
    uint32_t         irq_status;
    uint32_t         pin_levels;
    uint32_t         stop_reason;
    uint32_t         dma_remaining;
    uint32_t         dma_words;
} capture_raw_t;

typedef struct
{
    uint32_t completed;
    uint32_t dma_full;
    uint32_t fifo_stall;
    uint32_t pauses;
    uint32_t armed_while_high;
    uint32_t max_rearm_us;
    uint32_t self_test_flags;
    uint32_t self_test_word;
    uint32_t self_test_end_pc;
    uint32_t self_test_irq;
    uint32_t eof_interrupts;
    uint32_t dma_disabled_stops;
} capture_hw_stats_t;

/** @brief All four ownership APIs execute only on pinned Core 1. */
bool capture_hw_init(void);
bool capture_hw_take(capture_raw_t * p_raw);
void capture_hw_release(uint32_t slot);
/** @brief Atomic snapshot; safe for Core 0 diagnostic reader. */
void capture_hw_stats(capture_hw_stats_t * p_stats);

#endif /* CAPTURE_HW_H */

/*** end of file ***/
