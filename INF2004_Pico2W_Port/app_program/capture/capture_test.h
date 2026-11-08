/** @file capture_test.h
 * @brief Bounded, Core 0-only accounting for the PC's marked UDP test batches.
 */
#ifndef CAPTURE_TEST_H
#define CAPTURE_TEST_H

#include <stdbool.h> /* Occupied run records. */
#include <stddef.h>  /* Frame lengths. */
#include <stdint.h>  /* Wire bytes and bounded counters. */

#define CAPTURE_TEST_RUNS         4u
#define CAPTURE_TEST_MAX_PACKETS  10000u
#define CAPTURE_TEST_BITMAP_BYTES ((CAPTURE_TEST_MAX_PACKETS + 7u) / 8u)

typedef struct
{
    bool     b_used;
    uint8_t  source_mac[6];
    uint8_t  source_ip[4];
    uint32_t run_id;
    uint32_t expected;
    uint32_t unique;
    uint32_t duplicates;
    uint32_t reordered;
    uint32_t conflicts;
    uint32_t highest_sequence;
    uint16_t payload_bytes;
    uint8_t  seen[CAPTURE_TEST_BITMAP_BYTES];
} capture_test_run_t;

typedef struct
{
    capture_test_run_t runs[CAPTURE_TEST_RUNS];
    uint32_t           rejected;
    uint32_t           run_capacity_drops;
} capture_test_tracker_t;

typedef enum
{
    CAPTURE_TEST_BACKGROUND,
    CAPTURE_TEST_UNIQUE,
    CAPTURE_TEST_DUPLICATE,
    CAPTURE_TEST_REJECTED,
    CAPTURE_TEST_CAPACITY
} capture_test_result_t;

/** @brief Clear all run results; call only before capture starts. */
void capture_test_init(capture_test_tracker_t * p_tracker);
/** @brief Inspect an already FCS-verified Ethernet frame, excluding its FCS.
 * @note Core 0 consumer owns this tracker. No allocation, network replies or
 * IP reassembly; at most two VLAN tags. Only the exact PC test format counts.
 * This diagnostic is not an IP/UDP stack or protocol checksum validator.
 */
capture_test_result_t capture_test_observe(capture_test_tracker_t * p_tracker,
                                           const uint8_t *          p_data,
                                           size_t                   length);

#endif /* CAPTURE_TEST_H */

/*** end of file ***/
