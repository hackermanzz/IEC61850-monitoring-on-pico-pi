/** @file module.c
 *
 * @brief One sentence that describes what this module is for.
 *
 * @par
 * Sections appear in this order (BARR-C 4.3.b): comment block, includes,
 * constants and types, static data, private prototypes, public functions,
 * private functions.
 */

#include <stdbool.h>
#include <stdint.h>

#include "module.h"

// Private constants and types.
//
#define READY_THRESHOLD (2u)

// Module-level data. Names start with g_; volatile if an ISR or another
// task can also reach them.
//
static module_state_t g_state = {0};

// Private function prototypes.
//
static void state_reset(void);

/*!
 * @brief Prepare the module for use.
 */
void
module_init (void)
{
    state_reset();
}

/*!
 * @brief Report whether the module has seen enough items to be ready.
 *
 * @return True once the module is ready.
 */
bool
module_is_ready (void)
{
    return (g_state.b_is_ready);
}

/*!
 * @brief Return the module state to its power-on values.
 */
static void
state_reset (void)
{
    g_state.count      = 0u;
    g_state.b_is_ready = (g_state.count >= READY_THRESHOLD);
}

/*** end of file ***/
