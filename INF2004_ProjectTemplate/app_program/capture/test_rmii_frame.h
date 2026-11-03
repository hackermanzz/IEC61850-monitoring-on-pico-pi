/** @file test_rmii_frame.h
 *
 * @brief Test cases for the RMII frame helpers (rmii_frame.c): CRC-32,
 * frame length recovery and sample decoding.
 *
 * @par
 * The cases use no hardware and no kernel, so the same cases run on the
 * host (testing/capture/host_test_main.c) and on the board (capture_test()).
 * Built only when APP_TEST is 1.
 */
#ifndef TEST_RMII_FRAME_H
#define TEST_RMII_FRAME_H

#include <stdbool.h>
#include <stddef.h>

size_t test_rmii_frame_count(void);
bool   test_rmii_frame_run(size_t index, char const ** pp_id,
                           char const ** pp_description);

#endif /* TEST_RMII_FRAME_H */

/*** end of file ***/
