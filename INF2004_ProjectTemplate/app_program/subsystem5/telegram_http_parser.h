#ifndef TELEGRAM_HTTP_PARSER_H
#define TELEGRAM_HTTP_PARSER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TELEGRAM_HTTP_HEADER_CAPACITY (768U)
#define TELEGRAM_HTTP_CHUNK_LINE_CAPACITY (16U)
#define TELEGRAM_JSON_MAX_DEPTH (16U)
#define TELEGRAM_JSON_SCALAR_CAPACITY (32U)
#define TELEGRAM_JSON_OK_KEY_STORAGE (3U)
#define TELEGRAM_CHUNK_SIZE (0U)
#define TELEGRAM_CHUNK_SIZE_LF (1U)
#define TELEGRAM_CHUNK_DATA (2U)
#define TELEGRAM_CHUNK_DATA_CR (3U)
#define TELEGRAM_CHUNK_DATA_LF (4U)
#define TELEGRAM_CHUNK_TRAILER (5U)
#define TELEGRAM_CHUNK_TRAILER_LF (6U)
#define TELEGRAM_CHUNK_DONE (7U)

typedef struct
{
    char     headers[TELEGRAM_HTTP_HEADER_CAPACITY];
    char     json_key[TELEGRAM_JSON_OK_KEY_STORAGE];
    char     json_primitive[TELEGRAM_JSON_SCALAR_CAPACITY];
    uint8_t  json_container_stack[TELEGRAM_JSON_MAX_DEPTH];
    uint8_t  json_state_stack[TELEGRAM_JSON_MAX_DEPTH];
    size_t   header_length;
    uint32_t body_received;
    uint32_t content_length;
    uint32_t chunk_remaining;
    uint16_t http_status;
    uint16_t json_unicode_value;
    uint8_t  chunk_line_length;
    uint8_t  chunk_state;
    uint8_t  json_depth;
    uint8_t  json_string_role;
    uint8_t  json_string_escape;
    uint8_t  json_unicode_digits;
    uint8_t  json_utf8_remaining;
    uint8_t  json_utf8_next_min;
    uint8_t  json_utf8_next_max;
    uint8_t  json_key_length;
    uint8_t  json_key_is_ok;
    uint8_t  json_ok_count;
    uint8_t  json_primitive_length;
    uint8_t  json_primitive_is_ok;
    uint8_t  json_awaiting_ok_value;
    uint8_t  json_root_started;
    uint8_t  framing_mode;
    uint8_t  state;
    bool     json_string_active;
    bool     json_primitive_active;
    bool     json_complete;
    bool     json_api_ok;
    bool     failed;
    bool     complete;
} telegram_http_parser_t;

/* Initialize one parser instance before feeding a response in arrival order. */
void telegram_http_parser_init (telegram_http_parser_t * parser);
/* Feed arbitrary fragments; returns false permanently after a parse error. */
bool telegram_http_parser_feed (telegram_http_parser_t * parser,
                                const uint8_t * data, size_t length);
bool telegram_http_parser_succeeded (const telegram_http_parser_t * parser);
bool telegram_http_form_encode (char * destination, size_t destination_capacity,
                                const char * source);

#endif
