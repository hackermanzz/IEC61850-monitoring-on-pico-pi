/** @file tls_calendar.c
 * @brief Reentrant UTC conversion for certificate checks, without libc state.
 */
#include "tls_calendar.h"
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

struct tm *
mbedtls_platform_gmtime_r (const time_t * p_seconds, struct tm * p_result)
{
    static const unsigned int days_in_month[12] = {
        31u, 28u, 31u, 30u, 31u, 30u, 31u, 31u, 30u, 31u, 30u, 31u};
    uint64_t     days      = 0u;
    uint64_t     remaining = 0u;
    unsigned int year      = 1970u;
    unsigned int month     = 0u;
    unsigned int year_days = 0u;
    bool         leap      = false;
    if ((NULL == p_seconds) || (NULL == p_result) || (0 > *p_seconds)
        || (UINT64_C(253402300799) < (uint64_t) *p_seconds))
    {
        return NULL;
    }
    *p_result         = (struct tm) {0};
    days              = (uint64_t) *p_seconds / 86400u;
    remaining         = (uint64_t) *p_seconds % 86400u;
    p_result->tm_sec  = (int) (remaining % 60u);
    p_result->tm_min  = (int) (remaining / 60u % 60u);
    p_result->tm_hour = (int) (remaining / 3600u);
    p_result->tm_wday = (int) ((days + 4u) % 7u);
    for (;;)
    {
        leap =
            (0u == year % 4u) && ((0u != year % 100u) || (0u == year % 400u));
        year_days = leap ? 366u : 365u;
        if (days < year_days)
        {
            break;
        }
        days -= year_days;
        year++;
    }
    p_result->tm_year = (int) year - 1900;
    p_result->tm_yday = (int) days;
    while (12u > month)
    {
        unsigned int count =
            days_in_month[month] + ((leap && (1u == month)) ? 1u : 0u);
        if (days < count)
        {
            break;
        }
        days -= count;
        month++;
    }
    p_result->tm_mon  = (int) month;
    p_result->tm_mday = (int) days + 1;
    return p_result;
}

/*** end of file ***/
