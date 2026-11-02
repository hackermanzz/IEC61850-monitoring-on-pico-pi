/** @file module.h
 *
 * @brief One sentence that describes what this module is for.
 *
 * @par
 * Optional details: ownership, which task or core may call it, and any
 * assumptions a caller must know about.
 */
#ifndef MODULE_H
#define MODULE_H

#include <stdbool.h>
#include <stdint.h>

// Public constants. Macro names contain no lowercase letters.
//
#define MODULE_ITEM_COUNT (4u)

// Public types are named <module>_<name>_t.
//
typedef struct
{
    uint32_t count;
    bool     b_is_ready;
} module_state_t;

// Public functions are named <module>_<verb or question>.
//
void module_init(void);
bool module_is_ready(void);

#endif /* MODULE_H */

/*** end of file ***/
