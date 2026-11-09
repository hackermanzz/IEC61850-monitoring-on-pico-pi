/** @file analysis_port.h
 * @brief One Core 0 owner bridges verified capture frames to the Pico 1 models.
 */
#ifndef ANALYSIS_PORT_H
#define ANALYSIS_PORT_H

#include <stdbool.h>
#include <stdint.h>
#include "../capture/capture_decode.h"

typedef struct
{
    uint32_t received;
    uint32_t accepted;
    uint32_t rejected;
    uint32_t background;
    uint32_t goose_seen;
    uint32_t sv_seen;
    uint32_t iec_rejected;
    uint32_t oversize;
    uint32_t windows;
    uint32_t goose_windows;
    uint32_t sv_windows;
    uint32_t positive_windows;
    uint32_t gaps;
    uint32_t restarts;
    uint32_t stream_resets;
    uint32_t last_protocol;
    uint32_t last_label;
    uint32_t last_probability_ppm;
    uint32_t last_us;
    uint32_t max_us;
    uint32_t max_window_us;
    uint32_t last_frame_age_us;
    uint32_t max_frame_age_us;
    uint64_t total_us;
} analysis_port_stats_t;

/** @brief Clear state once, before the consumer receives any frames. */
void analysis_port_init(void);
/** @brief Synthetic parser/model/evidence check; call only before live input.
 */
bool analysis_port_self_check(void);
/** @brief Borrow a frame only until return; caller still releases it once. */
void analysis_port_observe(const capture_frame_t * p_frame);
/** @brief Only the Core 0 consumer may poll and read this state. */
void analysis_port_poll(uint64_t now_us);
void analysis_port_stats(analysis_port_stats_t * p_stats);

#endif /* ANALYSIS_PORT_H */

/*** end of file ***/
