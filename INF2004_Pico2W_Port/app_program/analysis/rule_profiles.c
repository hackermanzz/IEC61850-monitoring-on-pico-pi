/** @file rule_profiles.c
 *
 * @brief The trusted stream profiles used by the IEC 61850 rule checks.
 *
 * @par
 * Replace the table with trusted profiles from the SCD/SCL file or a verified
 * lab configuration. No publisher identity is guessed.
 */

#include <stddef.h>

#include "rule_profiles.h"

#if MONITOR_LAB_PROFILES

// NOTE: Explicit direct-cable lab profiles for tools/iec61850_publishers.py.
// These identities and rates are not a learned or production allow-list.
//
#define PROFILE_COUNT (2u)

static iec_rules_profile_t const g_profiles[IEC_RULE_MAX_PROFILES] = {
    {
        .protocol        = IEC_RULES_PROTOCOL_GOOSE,
        .conf_rev        = 1u,
        .entries         = 1u,
        .appid           = 0x1001u,
        .source          = {0x02u, 0x00u, 0x00u, 0x00u, 0x01u, 0x01u},
        .destination     = {0x01u, 0x0Cu, 0xCDu, 0x01u, 0x00u, 0x01u},
        .p_id            = "simpleIOGenericIO/LLN0$GO$gcbAnalogValues6",
        .p_dataset       = "simpleIOGenericIO/LLN0$AnalogValues6",
        .min_interval_us = 400000u,
        .max_interval_us = 700000u,
        .audit_windows   = 8u,
        .audit_us        = 1000000u,
    },
    {
        .protocol        = IEC_RULES_PROTOCOL_SV,
        .conf_rev        = 1u,
        .appid           = 0x4001u,
        .source          = {0x02u, 0x00u, 0x00u, 0x00u, 0x01u, 0x02u},
        .destination     = {0x01u, 0x0Cu, 0xCDu, 0x04u, 0x00u, 0x01u},
        .p_id            = "svpub_values_bus1",
        .sv_modulus      = 4000u,
        .sv_frame_step   = 1u,
        .min_interval_us = 400000u,
        .max_interval_us = 700000u,
        .audit_windows   = 8u,
        .audit_us        = 1000000u,
    },
};

#else /* !MONITOR_LAB_PROFILES */

#define PROFILE_COUNT (0u)

static iec_rules_profile_t const g_profiles[IEC_RULE_MAX_PROFILES] = {{0}};

#endif /* MONITOR_LAB_PROFILES */

_Static_assert(PROFILE_COUNT <= IEC_RULE_MAX_PROFILES,
               "too many IEC rule profiles");

/*!
 * @brief Give the profile table.
 *
 * @param[out] p_count Receives the number of profiles in use.
 *
 * @return The table.
 */
iec_rules_profile_t const *
rule_profiles_table (size_t * p_count)
{
    if (NULL != p_count)
    {
        *p_count = PROFILE_COUNT;
    }

    return (g_profiles);
}

/*** end of file ***/
