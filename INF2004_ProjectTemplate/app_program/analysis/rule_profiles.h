/** @file rule_profiles.h
 *
 * @brief The trusted stream profiles used by the IEC 61850 rule checks, and
 * the switch that lets clean windows skip the model.
 *
 * @par
 * Build with MONITOR_LAB_PROFILES=1 for the direct-cable lab publishers;
 * otherwise no stream is profiled and every window runs the model.
 */
#ifndef RULE_PROFILES_H
#define RULE_PROFILES_H

#include <stddef.h>

#include "iec_rules.h"

// WARNING: Off by default. Setting this to 1 changes detection coverage:
// valid payload-only attacks can pass between audits. Measure before enabling.
// Unknown or incompletely configured streams always run the model.
//
#ifndef IEC_RULE_GATE_ENABLED
#define IEC_RULE_GATE_ENABLED (0)
#endif

#if (IEC_RULE_GATE_ENABLED != 0) && (IEC_RULE_GATE_ENABLED != 1)
#error "IEC_RULE_GATE_ENABLED must be 0 or 1"
#endif

iec_rules_profile_t const * rule_profiles_table(size_t * p_count);

#endif /* RULE_PROFILES_H */

/*** end of file ***/
