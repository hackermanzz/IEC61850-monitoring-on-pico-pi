#ifndef TELEGRAM_STUB_PICO_STDLIB_H
#define TELEGRAM_STUB_PICO_STDLIB_H

#include <stdint.h>

typedef uint64_t absolute_time_t;
absolute_time_t get_absolute_time(void);
uint32_t to_ms_since_boot(absolute_time_t time);

#endif
