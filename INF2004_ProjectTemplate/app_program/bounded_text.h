#ifndef MONITOR_BOUNDED_TEXT_H
#define MONITOR_BOUNDED_TEXT_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    char *data;
    size_t capacity, length;
    bool ok;
} monitor_text_t;

static inline monitor_text_t monitor_text_begin(char *data, size_t capacity)
{
    monitor_text_t text = {data, capacity, 0, data != NULL && capacity != 0};
    if (text.ok) data[0] = '\0';
    return text;
}

static inline void monitor_text_char(monitor_text_t *text, char value)
{
    if (!text->ok) return;
    if (text->length + 1 >= text->capacity) { text->ok = false; return; }
    text->data[text->length++] = value;
    text->data[text->length] = '\0';
}

static inline void monitor_text_string(monitor_text_t *text, const char *value)
{
    if (value == NULL) { text->ok = false; return; }
    while (text->ok && *value) monitor_text_char(text, *value++);
}

static inline void monitor_text_u32(monitor_text_t *text, uint32_t value)
{
    char digits[10];
    size_t count = 0;
    do { digits[count++] = (char)('0' + value % 10); value /= 10; } while (value);
    while (count) monitor_text_char(text, digits[--count]);
}
#endif
