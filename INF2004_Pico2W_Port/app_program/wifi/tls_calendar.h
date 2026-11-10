#ifndef TLS_CALENDAR_H
#define TLS_CALENDAR_H
#include <time.h>
struct tm * mbedtls_platform_gmtime_r(const time_t * p_seconds,
                                      struct tm *    p_result);
#endif

/*** end of file ***/
