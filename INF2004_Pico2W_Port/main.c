#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
#include "pico/stdlib.h"
#include "hardware/clocks.h"
#include "hardware/timer.h"


uint64_t port_time_us(void){
    return time_us_64();
}

int main(void) 
{
    
    // Initialize console output.
    stdio_init_all();

    for (;;) 
    {
        printf(
            "clk_sys=%" PRIu32 "Hz, time=%" PRIu64 " us\n",
            clock_get_hz(clk_sys),
            port_time_us()
        );
        sleep_ms(1000);
    }

}