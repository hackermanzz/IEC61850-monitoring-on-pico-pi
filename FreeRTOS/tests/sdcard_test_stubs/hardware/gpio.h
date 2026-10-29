#ifndef SDCARD_TEST_GPIO_H
#define SDCARD_TEST_GPIO_H
#include <stdbool.h>
#define GPIO_FUNC_SPI (1U)
#define GPIO_OUT (1U)
void gpio_init (unsigned int pin);
void gpio_set_dir (unsigned int pin, bool output);
void gpio_put (unsigned int pin, bool high);
void gpio_set_function (unsigned int pin, unsigned int function);
#endif
