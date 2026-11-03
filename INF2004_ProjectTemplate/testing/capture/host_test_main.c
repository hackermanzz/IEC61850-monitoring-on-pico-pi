/** @file host_test_main.c
 *
 * @brief Host (PC) runner for the RMII frame test cases.
 *
 * @par
 * Runs the same cases as the on-board test, without hardware. From the
 * repository root:
 *
 *     gcc -std=gnu11 -Wall -Wextra -DAPP_TEST=1
 *         -IINF2004_ProjectTemplate/app_program/capture
 *         INF2004_ProjectTemplate/testing/capture/host_test_main.c
 *         INF2004_ProjectTemplate/app_program/capture/test_rmii_frame.c
 *         INF2004_ProjectTemplate/app_program/capture/rmii_frame.c
 *         -o rf_test
 *     ./rf_test
 *
 * The output uses the same [TEST] line format as the board.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include "host_test_main.h"
#include "test_rmii_frame.h"

#define EXIT_ALL_PASSED  (0)
#define EXIT_SOME_FAILED (1)

/*!
 * @brief Run every RMII frame test case and print the results.
 *
 * @return 0 if every case passed, otherwise 1.
 */
int
main (void)
{
    size_t passed = 0u;
    size_t failed = 0u;
    size_t index  = 0u;

    for (index = 0u; index < test_rmii_frame_count(); ++index)
    {
        char const * p_id          = "?";
        char const * p_description = "?";

        if (test_rmii_frame_run(index, &p_id, &p_description))
        {
            passed++;
            printf("[TEST] %s PASS  %s\n", p_id, p_description);
        }
        else
        {
            failed++;
            printf("[TEST] %s FAIL  %s\n", p_id, p_description);
        }
    }

    printf("[TEST] rmii_frame SUMMARY %zu passed, %zu failed\n", passed,
           failed);

    return ((0u == failed) ? EXIT_ALL_PASSED : EXIT_SOME_FAILED);
}

/*** end of file ***/
