#include "telegram_http_parser.h"

#include <string.h>

#define HTTP_STATE_HEADERS (0U)
#define HTTP_STATE_BODY (1U)
#define HTTP_STATE_DONE (2U)
#define HTTP_FRAMING_LENGTH (1U)
#define HTTP_FRAMING_CHUNKED (2U)
#define JSON_OBJECT (1U)
#define JSON_ARRAY (2U)
#define JSON_EXPECT_VALUE (0U)
#define JSON_EXPECT_KEY (1U)
#define JSON_EXPECT_KEY_OR_END (2U)
#define JSON_EXPECT_COLON (3U)
#define JSON_EXPECT_SEPARATOR (4U)
#define JSON_EXPECT_VALUE_OR_END (5U)
#define JSON_STRING_NONE (0U)
#define JSON_STRING_KEY (1U)
#define JSON_STRING_VALUE (2U)
#define JSON_SCALAR_NONE (0U)
#define JSON_SCALAR_TRUE (1U)
#define JSON_SCALAR_FALSE (2U)
#define JSON_SCALAR_NULL (3U)
#define JSON_SCALAR_NUMBER (4U)
#define JSON_MAX_BODY (2048U)
#define DECIMAL_RADIX (10U)
#define HEXADECIMAL_RADIX (16U)
#define HEXADECIMAL_ALPHA_OFFSET (10U)
#define HEXADECIMAL_NIBBLE_SHIFT (4U)
#define HEXADECIMAL_NIBBLE_MASK (0x0FU)
#define HTTP_VERSION_PREFIX_LENGTH (7U)
#define HTTP_VERSION_MINOR_INDEX (7U)
#define HTTP_STATUS_SEPARATOR_INDEX (8U)
#define HTTP_STATUS_CODE_START (9U)
#define HTTP_STATUS_FIRST_DIGIT (0U)
#define HTTP_STATUS_SECOND_DIGIT (1U)
#define HTTP_STATUS_THIRD_DIGIT (2U)
#define HTTP_STATUS_CODE_LENGTH (3U)
#define HTTP_STATUS_CODE_MINIMUM_LINE_LENGTH (12U)
#define HTTP_STATUS_CODE_END (HTTP_STATUS_CODE_START + HTTP_STATUS_CODE_LENGTH)
#define HEADER_VALUE_AFTER_COLON_OFFSET (1U)
#define HTTP_STATUS_FIRST_DIGIT_FACTOR (100U)
#define HTTP_STATUS_SECOND_DIGIT_FACTOR (10U)
#define CRLF_LENGTH (2U)
#define HTTP_HEADER_TERMINATOR_LENGTH (4U)
#define JSON_OK_KEY_LENGTH (2U)
#define JSON_OK_KEY_CAPACITY (3U)
#define JSON_UNICODE_HEX_DIGITS (4U)
#define JSON_ESCAPED_ASCII_MIN (0x20U)
#define JSON_ESCAPED_ASCII_MAX (0x7EU)
#define JSON_CONTROL_BYTE_LIMIT (0x20U)
#define JSON_UTF8_CONTINUATION_MIN (0x80U)
#define JSON_UTF8_CONTINUATION_MAX (0xBFU)
#define JSON_UTF8_TWO_BYTE_MIN (0xC2U)
#define JSON_UTF8_TWO_BYTE_MAX (0xDFU)
#define JSON_UTF8_THREE_BYTE_MIN (0xE0U)
#define JSON_UTF8_THREE_BYTE_MAX (0xEFU)
#define JSON_UTF8_FOUR_BYTE_MIN (0xF0U)
#define JSON_UTF8_FOUR_BYTE_MAX (0xF4U)
#define JSON_UTF8_E0_CONTINUATION_MIN (0xA0U)
#define JSON_UTF8_ED_CONTINUATION_MAX (0x9FU)
#define JSON_UTF8_SURROGATE_START (0xEDU)
#define JSON_UTF8_F0_CONTINUATION_MIN (0x90U)
#define JSON_UTF8_F4_CONTINUATION_MAX (0x8FU)
#define JSON_UTF8_TWO_BYTE_CONTINUATIONS (1U)
#define JSON_UTF8_THREE_BYTE_CONTINUATIONS (2U)
#define JSON_UTF8_FOUR_BYTE_CONTINUATIONS (3U)
#define JSON_TRAILING_NUL_INDEX (2U)
#define HTTP_SUCCESS_STATUS_MIN (200U)
#define HTTP_SUCCESS_STATUS_LIMIT (300U)

static char
ascii_lower (char value)
{
    if (value >= 'A' && value <= 'Z')
    {
        return (char) (value + ('a' - 'A'));
    }
    return value;
}

static bool
equals_case_insensitive (const char * left, const char * right)
{
    size_t index = 0U;
    while (left[index] != '\0' && right[index] != '\0')
    {
        if (ascii_lower(left[index]) != ascii_lower(right[index]))
        {
            return false;
        }
        index++;
    }
    return left[index] == '\0' && right[index] == '\0';
}

static const char *
skip_spaces (const char * text)
{
    while (*text == ' ' || *text == '\t')
    {
        text++;
    }
    return text;
}

static bool
parse_decimal (const char * text, uint32_t * value)
{
    uint32_t result = 0U;
    if (*text == '\0')
    {
        return false;
    }
    while (*text != '\0')
    {
        const char digit = *text;
        if (digit < '0' || digit > '9' ||
            result > (UINT32_MAX - (uint32_t) (digit - '0')) / DECIMAL_RADIX)
        {
            return false;
        }
        result = result * DECIMAL_RADIX + (uint32_t) (digit - '0');
        text++;
    }
    *value = result;
    return true;
}

static bool
parse_headers (telegram_http_parser_t * parser)
{
    char * line        = parser->headers;
    char * line_end    = strstr(line, "\r\n");
    bool   has_length  = false;
    bool   has_chunked = false;
    if (line_end == NULL ||
        strncmp(line, "HTTP/1.", HTTP_VERSION_PREFIX_LENGTH) != 0 ||
        line[HTTP_VERSION_MINOR_INDEX] < '0' ||
        line[HTTP_VERSION_MINOR_INDEX] > '1' ||
        line[HTTP_STATUS_SEPARATOR_INDEX] != ' ' ||
        line_end - line < HTTP_STATUS_CODE_MINIMUM_LINE_LENGTH ||
        line[HTTP_STATUS_CODE_START] < '0' ||
        line[HTTP_STATUS_CODE_START] > '9' ||
        line[HTTP_STATUS_CODE_START + HTTP_STATUS_SECOND_DIGIT] < '0' ||
        line[HTTP_STATUS_CODE_START + HTTP_STATUS_SECOND_DIGIT] > '9' ||
        line[HTTP_STATUS_CODE_START + HTTP_STATUS_THIRD_DIGIT] < '0' ||
        line[HTTP_STATUS_CODE_START + HTTP_STATUS_THIRD_DIGIT] > '9' ||
        (line_end - line > HTTP_STATUS_CODE_END &&
         line[HTTP_STATUS_CODE_END] != ' '))
    {
        return false;
    }
    parser->http_status =
        (uint16_t) ((line[HTTP_STATUS_CODE_START + HTTP_STATUS_FIRST_DIGIT] -
                     '0') *
                        HTTP_STATUS_FIRST_DIGIT_FACTOR +
                    (line[HTTP_STATUS_CODE_START + HTTP_STATUS_SECOND_DIGIT] -
                     '0') *
                        HTTP_STATUS_SECOND_DIGIT_FACTOR +
                    (line[HTTP_STATUS_CODE_START + HTTP_STATUS_THIRD_DIGIT] -
                     '0'));
    line = line_end + CRLF_LENGTH;
    while (*line != '\0')
    {
        char *       colon     = NULL;
        const char * value     = NULL;
        char *       value_end = NULL;
        line_end               = strstr(line, "\r\n");
        if (line_end == NULL)
        {
            return false;
        }
        if (line_end == line)
        {
            break;
        }
        colon = (char *) memchr(line, ':', (size_t) (line_end - line));
        if (colon == NULL)
        {
            return false;
        }
        *line_end = '\0';
        *colon    = '\0';
        value     = skip_spaces(colon + HEADER_VALUE_AFTER_COLON_OFFSET);
        value_end = line_end;
        while (value_end > value &&
               (value_end[-1] == ' ' || value_end[-1] == '\t'))
        {
            --value_end;
        }
        *value_end = '\0';
        if (equals_case_insensitive(line, "content-length"))
        {
            if (has_length || !parse_decimal(value, &parser->content_length) ||
                parser->content_length == 0U ||
                parser->content_length > JSON_MAX_BODY)
            {
                return false;
            }
            has_length = true;
        }
        else if (equals_case_insensitive(line, "transfer-encoding"))
        {
            if (has_chunked || !equals_case_insensitive(value, "chunked"))
            {
                return false;
            }
            has_chunked = true;
        }
        line = line_end + CRLF_LENGTH;
    }
    if (has_length == has_chunked)
    {
        return false;
    }
    parser->framing_mode =
        has_chunked ? HTTP_FRAMING_CHUNKED : HTTP_FRAMING_LENGTH;
    parser->state = HTTP_STATE_BODY;
    return true;
}

static bool
json_is_space (uint8_t value)
{
    return value == ' ' || value == '\t' || value == '\r' || value == '\n';
}

static void
json_append_key_byte (telegram_http_parser_t * parser, uint8_t value)
{
    if (parser->json_string_role == JSON_STRING_KEY)
    {
        if (parser->json_key_length < JSON_OK_KEY_LENGTH)
        {
            parser->json_key[parser->json_key_length] = (char) value;
        }
        else
        {
            parser->json_key_is_ok = 0U;
        }
        parser->json_key_length++;
    }
}

static bool
json_complete_value (telegram_http_parser_t * parser)
{
    if (parser->json_depth == 0U)
    {
        if (parser->json_root_started == 0U || parser->json_complete)
        {
            return false;
        }
        parser->json_complete = true;
        return true;
    }
    const uint8_t parent = parser->json_depth - 1U;
    if (parser->json_state_stack[parent] != JSON_EXPECT_VALUE &&
        parser->json_state_stack[parent] != JSON_EXPECT_VALUE_OR_END)
    {
        return false;
    }
    parser->json_state_stack[parent] = JSON_EXPECT_SEPARATOR;
    return true;
}

static bool
json_start_container (telegram_http_parser_t * parser, uint8_t type)
{
    if (parser->json_depth >= TELEGRAM_JSON_MAX_DEPTH)
    {
        return false;
    }
    if (parser->json_depth == 0U)
    {
        if (parser->json_root_started != 0U || type != JSON_OBJECT)
        {
            return false;
        }
        parser->json_root_started = 1U;
    }
    else if (parser->json_depth == 1U && parser->json_awaiting_ok_value != 0U)
    {
        return false;
    }
    else if (parser->json_state_stack[parser->json_depth - 1U] !=
                 JSON_EXPECT_VALUE &&
             parser->json_state_stack[parser->json_depth - 1U] !=
                 JSON_EXPECT_VALUE_OR_END)
    {
        return false;
    }
    parser->json_container_stack[parser->json_depth] = type;
    parser->json_state_stack[parser->json_depth] =
        type == JSON_OBJECT ? JSON_EXPECT_KEY_OR_END : JSON_EXPECT_VALUE_OR_END;
    parser->json_depth++;
    return true;
}

static bool
json_start_string (telegram_http_parser_t * parser)
{
    if (parser->json_depth == 0U)
    {
        return false;
    }
    const uint8_t level     = parser->json_depth - 1U;
    const uint8_t container = parser->json_container_stack[level];
    const uint8_t state     = parser->json_state_stack[level];
    if (container == JSON_OBJECT &&
        (state == JSON_EXPECT_KEY || state == JSON_EXPECT_KEY_OR_END))
    {
        parser->json_string_role = JSON_STRING_KEY;
        parser->json_key_is_ok   = 1U;
        parser->json_key_length  = 0U;
    }
    else if (state == JSON_EXPECT_VALUE || state == JSON_EXPECT_VALUE_OR_END)
    {
        if (parser->json_depth == 1U && parser->json_awaiting_ok_value != 0U)
        {
            return false;
        }
        parser->json_string_role = JSON_STRING_VALUE;
    }
    else
    {
        return false;
    }
    parser->json_string_active  = true;
    parser->json_string_escape  = 0U;
    parser->json_unicode_digits = 0U;
    parser->json_utf8_remaining = 0U;
    parser->json_utf8_next_min  = JSON_UTF8_CONTINUATION_MIN;
    parser->json_utf8_next_max  = JSON_UTF8_CONTINUATION_MAX;
    return true;
}

static bool
json_escape_byte (telegram_http_parser_t * parser, uint8_t value,
                  bool * handled)
{
    uint16_t digit = 0U;
    *handled =
        parser->json_unicode_digits != 0U || parser->json_string_escape != 0U;
    if (parser->json_unicode_digits != 0U)
    {
        if ((value < '0' || value > '9') && (value < 'a' || value > 'f') &&
            (value < 'A' || value > 'F'))
        {
            return false;
        }
        if (value >= '0' && value <= '9')
        {
            digit = (uint16_t) (value - '0');
        }
        else if (value >= 'a' && value <= 'f')
        {
            digit = (uint16_t) (value - 'a' + HEXADECIMAL_ALPHA_OFFSET);
        }
        else
        {
            digit = (uint16_t) (value - 'A' + HEXADECIMAL_ALPHA_OFFSET);
        }
        parser->json_unicode_value =
            (uint16_t) (parser->json_unicode_value * HEXADECIMAL_RADIX + digit);
        parser->json_unicode_digits--;
        if (parser->json_unicode_digits == 0U)
        {
            if (parser->json_unicode_value >= JSON_ESCAPED_ASCII_MIN &&
                parser->json_unicode_value <= JSON_ESCAPED_ASCII_MAX)
            {
                json_append_key_byte(parser,
                                     (uint8_t) parser->json_unicode_value);
            }
            else if (parser->json_string_role == JSON_STRING_KEY)
            {
                parser->json_key_is_ok  = 0U;
                parser->json_key_length = JSON_OK_KEY_CAPACITY;
            }
        }
        return true;
    }
    if (!parser->json_string_escape)
    {
        return true;
    }
    parser->json_string_escape = 0U;
    if (value == 'u')
    {
        parser->json_unicode_digits = JSON_UNICODE_HEX_DIGITS;
        parser->json_unicode_value  = 0U;
        return true;
    }
    if (value != '"' && value != '\\' && value != '/' && value != 'b' &&
        value != 'f' && value != 'n' && value != 'r' && value != 't')
    {
        return false;
    }
    json_append_key_byte(parser, value);
    return true;
}

static bool
json_utf8_byte (telegram_http_parser_t * parser, uint8_t value, bool * handled)
{
    *handled = parser->json_utf8_remaining != 0U ||
               value >= JSON_UTF8_CONTINUATION_MIN;
    if (parser->json_utf8_remaining != 0U)
    {
        if (value < parser->json_utf8_next_min ||
            value > parser->json_utf8_next_max)
        {
            return false;
        }
        parser->json_utf8_remaining--;
        parser->json_utf8_next_min = JSON_UTF8_CONTINUATION_MIN;
        parser->json_utf8_next_max = JSON_UTF8_CONTINUATION_MAX;
    }
    else if (value >= JSON_UTF8_TWO_BYTE_MIN && value <= JSON_UTF8_TWO_BYTE_MAX)
    {
        parser->json_utf8_remaining = 1U;
    }
    else if (value >= JSON_UTF8_THREE_BYTE_MIN &&
             value <= JSON_UTF8_THREE_BYTE_MAX)
    {
        parser->json_utf8_remaining = JSON_UTF8_THREE_BYTE_CONTINUATIONS;
        if (value == JSON_UTF8_THREE_BYTE_MIN)
        {
            parser->json_utf8_next_min = JSON_UTF8_E0_CONTINUATION_MIN;
        }
        else if (value == JSON_UTF8_SURROGATE_START)
        {
            parser->json_utf8_next_max = JSON_UTF8_ED_CONTINUATION_MAX;
        }
    }
    else if (value >= JSON_UTF8_FOUR_BYTE_MIN &&
             value <= JSON_UTF8_FOUR_BYTE_MAX)
    {
        parser->json_utf8_remaining = JSON_UTF8_FOUR_BYTE_CONTINUATIONS;
        if (value == JSON_UTF8_FOUR_BYTE_MIN)
        {
            parser->json_utf8_next_min = JSON_UTF8_F0_CONTINUATION_MIN;
        }
        else if (value == JSON_UTF8_FOUR_BYTE_MAX)
        {
            parser->json_utf8_next_max = JSON_UTF8_F4_CONTINUATION_MAX;
        }
    }
    else if (*handled)
    {
        return false;
    }
    if (*handled && parser->json_string_role == JSON_STRING_KEY)
    {
        parser->json_key_is_ok  = 0U;
        parser->json_key_length = JSON_OK_KEY_CAPACITY;
    }
    return true;
}

static bool
json_close_string (telegram_http_parser_t * parser)
{
    parser->json_string_active = false;
    if (parser->json_string_role == JSON_STRING_KEY)
    {
        parser->json_state_stack[parser->json_depth - 1U] = JSON_EXPECT_COLON;
        parser->json_key_is_ok =
            parser->json_depth == 1U && parser->json_key_is_ok != 0U &&
            parser->json_key_length == JSON_OK_KEY_LENGTH &&
            parser->json_key[0] == 'o' && parser->json_key[1] == 'k';
        parser->json_key[JSON_TRAILING_NUL_INDEX] = '\0';
        parser->json_ok_count += parser->json_key_is_ok != 0U ? 1U : 0U;
        if (parser->json_ok_count > 1U)
        {
            return false;
        }
    }
    else
    {
        parser->json_state_stack[parser->json_depth - 1U] =
            JSON_EXPECT_SEPARATOR;
        if (parser->json_depth == 1U && parser->json_awaiting_ok_value != 0U)
        {
            return false;
        }
    }
    parser->json_string_role = JSON_STRING_NONE;
    return true;
}

static bool
json_string_byte (telegram_http_parser_t * parser, uint8_t value)
{
    bool handled = false;
    if (!json_escape_byte(parser, value, &handled))
    {
        return false;
    }
    if (handled)
    {
        return true;
    }
    if (value == '"')
    {
        return parser->json_utf8_remaining == 0U && json_close_string(parser);
    }
    if (value < JSON_CONTROL_BYTE_LIMIT)
    {
        return false;
    }
    if (!json_utf8_byte(parser, value, &handled))
    {
        return false;
    }
    if (handled)
    {
        return true;
    }
    if (value == '\\')
    {
        parser->json_string_escape = 1U;
    }
    else
    {
        json_append_key_byte(parser, value);
    }
    return true;
}

static bool
json_start_scalar (telegram_http_parser_t * parser, uint8_t value)
{
    if (parser->json_depth == 0U ||
        (parser->json_state_stack[parser->json_depth - 1U] !=
             JSON_EXPECT_VALUE &&
         parser->json_state_stack[parser->json_depth - 1U] !=
             JSON_EXPECT_VALUE_OR_END))
    {
        return false;
    }
    parser->json_primitive_active = true;
    parser->json_primitive_length = 0U;
    parser->json_primitive_is_ok  = 0U;
    if (parser->json_depth == 1U && parser->json_awaiting_ok_value != 0U)
    {
        if (value != 't' && value != 'f')
        {
            return false;
        }
        parser->json_primitive_is_ok =
            value == 't' ? JSON_SCALAR_TRUE : JSON_SCALAR_FALSE;
    }
    else if (value == 't')
    {
        parser->json_primitive_is_ok = JSON_SCALAR_TRUE;
    }
    else if (value == 'f')
    {
        parser->json_primitive_is_ok = JSON_SCALAR_FALSE;
    }
    else if (value == 'n')
    {
        parser->json_primitive_is_ok = JSON_SCALAR_NULL;
    }
    else if (value == '-' || (value >= '0' && value <= '9'))
    {
        parser->json_primitive_is_ok = JSON_SCALAR_NUMBER;
    }
    else
    {
        return false;
    }
    parser->json_primitive[parser->json_primitive_length++] = (char) value;
    return true;
}

static bool
json_finish_scalar (telegram_http_parser_t * parser)
{
    const uint8_t kind     = parser->json_primitive_is_ok;
    const char *  expected = kind == JSON_SCALAR_TRUE    ? "true"
                             : kind == JSON_SCALAR_FALSE ? "false"
                             : kind == JSON_SCALAR_NULL  ? "null"
                                                         : NULL;
    if (expected != NULL &&
        (strlen(expected) != parser->json_primitive_length ||
         memcmp(parser->json_primitive, expected,
                parser->json_primitive_length) != 0))
    {
        return false;
    }
    if (kind == JSON_SCALAR_NUMBER)
    {
        size_t index                    = 0U;
        bool   has_fraction_or_exponent = false;
        if (parser->json_primitive[index] == '-')
        {
            index++;
        }
        if (parser->json_primitive[index] == '0')
        {
            index++;
            if (index < parser->json_primitive_length &&
                parser->json_primitive[index] >= '0' &&
                parser->json_primitive[index] <= '9')
            {
                return false;
            }
        }
        else if (parser->json_primitive[index] >= '1' &&
                 parser->json_primitive[index] <= '9')
        {
            while (index < parser->json_primitive_length &&
                   parser->json_primitive[index] >= '0' &&
                   parser->json_primitive[index] <= '9')
            {
                index++;
            }
        }
        else
        {
            return false;
        }
        if (index < parser->json_primitive_length &&
            parser->json_primitive[index] == '.')
        {
            has_fraction_or_exponent = true;
            index++;
            const size_t fraction_start = index;
            while (index < parser->json_primitive_length &&
                   parser->json_primitive[index] >= '0' &&
                   parser->json_primitive[index] <= '9')
            {
                index++;
            }
            if (fraction_start == index)
            {
                return false;
            }
        }
        if (index < parser->json_primitive_length &&
            (parser->json_primitive[index] == 'e' ||
             parser->json_primitive[index] == 'E'))
        {
            has_fraction_or_exponent = true;
            index++;
            if (index < parser->json_primitive_length &&
                (parser->json_primitive[index] == '+' ||
                 parser->json_primitive[index] == '-'))
            {
                index++;
            }
            const size_t exponent_start = index;
            while (index < parser->json_primitive_length &&
                   parser->json_primitive[index] >= '0' &&
                   parser->json_primitive[index] <= '9')
            {
                index++;
            }
            if (exponent_start == index)
            {
                return false;
            }
        }
        (void) has_fraction_or_exponent;
        if (index != parser->json_primitive_length)
        {
            return false;
        }
    }
    parser->json_primitive_active = false;
    if (parser->json_depth == 1U && parser->json_awaiting_ok_value != 0U)
    {
        parser->json_api_ok            = kind == JSON_SCALAR_TRUE;
        parser->json_awaiting_ok_value = 0U;
    }
    return json_complete_value(parser);
}

static bool
json_primitive_byte (telegram_http_parser_t * parser, uint8_t value)
{
    if (value == ',' || value == '}' || value == ']' || json_is_space(value))
    {
        return json_finish_scalar(parser);
    }
    if (parser->json_primitive_length >= TELEGRAM_JSON_SCALAR_CAPACITY)
    {
        return false;
    }
    parser->json_primitive[parser->json_primitive_length++] = (char) value;
    return true;
}

static bool
json_byte (telegram_http_parser_t * parser, uint8_t value)
{
    if (parser->json_string_active)
    {
        return json_string_byte(parser, value);
    }
    if (parser->json_primitive_active && value != ',' && value != '}' &&
        value != ']' && !json_is_space(value))
    {
        return json_primitive_byte(parser, value);
    }
    if (parser->json_primitive_active && !json_finish_scalar(parser))
    {
        return false;
    }
    if (json_is_space(value))
    {
        return true;
    }
    if (parser->json_complete)
    {
        return false;
    }
    if (value == '{' || value == '[')
    {
        return json_start_container(parser,
                                    value == '{' ? JSON_OBJECT : JSON_ARRAY);
    }
    if (value == '}' || value == ']')
    {
        if (parser->json_depth == 0U ||
            (value == '}' &&
             parser->json_container_stack[parser->json_depth - 1U] !=
                 JSON_OBJECT) ||
            (value == ']' &&
             parser->json_container_stack[parser->json_depth - 1U] !=
                 JSON_ARRAY))
        {
            return false;
        }
        const uint8_t state = parser->json_state_stack[parser->json_depth - 1U];
        if (state != JSON_EXPECT_SEPARATOR &&
            !(state == JSON_EXPECT_KEY_OR_END && value == '}') &&
            !(state == JSON_EXPECT_VALUE_OR_END && value == ']'))
        {
            return false;
        }
        if (parser->json_depth == 1U && parser->json_ok_count != 1U)
        {
            return false;
        }
        parser->json_depth--;
        return json_complete_value(parser);
    }
    if (value == '"')
    {
        return json_start_string(parser);
    }
    if (parser->json_depth == 0U)
    {
        return false;
    }
    const uint8_t level = parser->json_depth - 1U;
    if (value == ':' && parser->json_container_stack[level] == JSON_OBJECT &&
        parser->json_state_stack[level] == JSON_EXPECT_COLON)
    {
        parser->json_state_stack[level] = JSON_EXPECT_VALUE;
        if (level == 0U && parser->json_key_is_ok != 0U)
        {
            parser->json_awaiting_ok_value = 1U;
        }
        return true;
    }
    if (value == ',' &&
        parser->json_state_stack[level] == JSON_EXPECT_SEPARATOR)
    {
        parser->json_state_stack[level] =
            parser->json_container_stack[level] == JSON_OBJECT
                ? JSON_EXPECT_KEY
                : JSON_EXPECT_VALUE;
        return true;
    }
    if (parser->json_state_stack[level] == JSON_EXPECT_VALUE ||
        parser->json_state_stack[level] == JSON_EXPECT_VALUE_OR_END)
    {
        return json_start_scalar(parser, value);
    }
    return false;
}

static bool
feed_body_byte (telegram_http_parser_t * parser, uint8_t value)
{
    if (parser->body_received >= JSON_MAX_BODY || !json_byte(parser, value))
    {
        return false;
    }
    parser->body_received++;
    return true;
}

static void
finish_http_body (telegram_http_parser_t * parser)
{
    parser->state    = HTTP_STATE_DONE;
    parser->complete = parser->json_complete && parser->json_depth == 0U &&
                       !parser->json_string_active &&
                       !parser->json_primitive_active;
}

static bool
feed_length_body (telegram_http_parser_t * parser, const uint8_t * data,
                  size_t length)
{
    size_t index = 0U;
    while (index < length && parser->body_received < parser->content_length)
    {
        if (!feed_body_byte(parser, data[index]))
        {
            return false;
        }
        index++;
    }
    if (index != length)
    {
        return false;
    }
    if (parser->body_received == parser->content_length)
    {
        if (parser->json_primitive_active && !json_finish_scalar(parser))
        {
            return false;
        }
        finish_http_body(parser);
    }
    return true;
}

static bool
feed_chunk_size_byte (telegram_http_parser_t * parser, uint8_t value)
{
    uint8_t digit = 0U;
    if (value == '\r')
    {
        parser->chunk_state = TELEGRAM_CHUNK_SIZE_LF;
        return true;
    }
    if (value >= '0' && value <= '9')
    {
        digit = (uint8_t) (value - '0');
    }
    else if (value >= 'a' && value <= 'f')
    {
        digit = (uint8_t) (value - 'a' + HEXADECIMAL_ALPHA_OFFSET);
    }
    else if (value >= 'A' && value <= 'F')
    {
        digit = (uint8_t) (value - 'A' + HEXADECIMAL_ALPHA_OFFSET);
    }
    else
    {
        return false;
    }
    if (parser->chunk_line_length >= TELEGRAM_HTTP_CHUNK_LINE_CAPACITY ||
        parser->chunk_remaining > (JSON_MAX_BODY - digit) / HEXADECIMAL_RADIX)
    {
        return false;
    }
    parser->chunk_remaining =
        parser->chunk_remaining * HEXADECIMAL_RADIX + digit;
    parser->chunk_line_length++;
    return true;
}

static bool
feed_chunked_body (telegram_http_parser_t * parser, const uint8_t * data,
                   size_t length)
{
    size_t index = 0U;
    while (index < length)
    {
        uint8_t value = 0U;
        value         = data[index];
        if (parser->chunk_state == TELEGRAM_CHUNK_SIZE)
        {
            if (!feed_chunk_size_byte(parser, value))
            {
                return false;
            }
        }
        else if (parser->chunk_state == TELEGRAM_CHUNK_SIZE_LF)
        {
            if (value != '\n' || parser->chunk_line_length == 0U)
            {
                return false;
            }
            parser->chunk_line_length = 0U;
            parser->chunk_state       = parser->chunk_remaining == 0U
                                            ? TELEGRAM_CHUNK_TRAILER
                                            : TELEGRAM_CHUNK_DATA;
        }
        else if (parser->chunk_state == TELEGRAM_CHUNK_DATA)
        {
            if (!feed_body_byte(parser, value))
            {
                return false;
            }
            parser->chunk_remaining--;
            if (parser->chunk_remaining == 0U)
            {
                parser->chunk_state = TELEGRAM_CHUNK_DATA_CR;
            }
        }
        else if (parser->chunk_state == TELEGRAM_CHUNK_DATA_CR)
        {
            if (value != '\r')
            {
                return false;
            }
            parser->chunk_state = TELEGRAM_CHUNK_DATA_LF;
        }
        else if (parser->chunk_state == TELEGRAM_CHUNK_DATA_LF)
        {
            if (value != '\n')
            {
                return false;
            }
            parser->chunk_state     = TELEGRAM_CHUNK_SIZE;
            parser->chunk_remaining = 0U;
        }
        else if (parser->chunk_state == TELEGRAM_CHUNK_TRAILER)
        {
            if (value == '\r')
            {
                parser->chunk_state = TELEGRAM_CHUNK_TRAILER_LF;
            }
            else
            {
                /* Trailer fields are intentionally unsupported and bounded. */
                return false;
            }
        }
        else if (parser->chunk_state == TELEGRAM_CHUNK_TRAILER_LF)
        {
            if (value != '\n')
            {
                return false;
            }
            if (parser->json_primitive_active && !json_finish_scalar(parser))
            {
                return false;
            }
            parser->chunk_state = TELEGRAM_CHUNK_DONE;
            finish_http_body(parser);
        }
        else
        {
            return false;
        }
        index++;
    }
    return true;
}

void
telegram_http_parser_init (telegram_http_parser_t * parser)
{
    if (parser != NULL)
    {
        memset(parser, 0, sizeof(*parser));
        parser->state       = HTTP_STATE_HEADERS;
        parser->chunk_state = TELEGRAM_CHUNK_SIZE;
    }
}

bool
telegram_http_parser_feed (telegram_http_parser_t * parser,
                           const uint8_t * data, size_t length)
{
    size_t index = 0U;
    if (parser == NULL || (data == NULL && length != 0U) || parser->failed)
    {
        return false;
    }
    if (parser->state == HTTP_STATE_DONE)
    {
        if (length == 0U)
        {
            return true;
        }
        parser->failed = true;
        return false;
    }
    while (index < length && parser->state == HTTP_STATE_HEADERS)
    {
        if (parser->header_length >= sizeof(parser->headers) - 1U)
        {
            parser->failed = true;
            return false;
        }
        parser->headers[parser->header_length++] = (char) data[index++];
        parser->headers[parser->header_length]   = '\0';
        if (parser->header_length >= HTTP_HEADER_TERMINATOR_LENGTH &&
            strcmp(&parser->headers[parser->header_length -
                                    HTTP_HEADER_TERMINATOR_LENGTH],
                   "\r\n\r\n") == 0 &&
            !parse_headers(parser))
        {
            parser->failed = true;
            return false;
        }
    }
    if (index < length && parser->state == HTTP_STATE_BODY)
    {
        const bool valid =
            parser->framing_mode == HTTP_FRAMING_LENGTH
                ? feed_length_body(parser, data + index, length - index)
                : feed_chunked_body(parser, data + index, length - index);
        if (!valid)
        {
            parser->failed = true;
            return false;
        }
    }
    return !parser->failed;
}

bool
telegram_http_parser_succeeded (const telegram_http_parser_t * parser)
{
    return parser != NULL && !parser->failed && parser->complete &&
           parser->http_status >= HTTP_SUCCESS_STATUS_MIN &&
           parser->http_status < HTTP_SUCCESS_STATUS_LIMIT &&
           parser->json_ok_count == 1U && parser->json_api_ok;
}

bool
telegram_http_form_encode (char * destination, size_t destination_capacity,
                           const char * source)
{
    static const char hex[]  = "0123456789ABCDEF";
    size_t            output = 0U;
    if (destination == NULL || source == NULL || destination_capacity == 0U)
    {
        return false;
    }
    while (*source != '\0')
    {
        const uint8_t value = (uint8_t) *source++;
        const bool    unreserved =
            (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z') ||
            (value >= '0' && value <= '9') || value == '-' || value == '_' ||
            value == '.' || value == '~';
        const size_t needed = unreserved || value == ' ' ? 1U : 3U;
        if (output > destination_capacity - 1U ||
            needed > destination_capacity - output - 1U)
        {
            return false;
        }
        if (unreserved)
        {
            destination[output++] = (char) value;
        }
        else if (value == ' ')
        {
            destination[output++] = '+';
        }
        else
        {
            destination[output++] = '%';
            destination[output++] = hex[value >> HEXADECIMAL_NIBBLE_SHIFT];
            destination[output++] = hex[value & HEXADECIMAL_NIBBLE_MASK];
        }
    }
    destination[output] = '\0';
    return true;
}
