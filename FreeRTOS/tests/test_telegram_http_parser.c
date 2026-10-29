#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "telegram_http_parser.h"

static bool
feed_all (telegram_http_parser_t * parser, const char * response)
{
    const size_t length = strlen(response);
    size_t       index  = 0U;
    while (index < length)
    {
        const size_t chunk     = index % 7U + 1U;
        const size_t remaining = length - index;
        const size_t count     = chunk < remaining ? chunk : remaining;
        if (!telegram_http_parser_feed(
                parser, (const uint8_t *) response + index, count))
        {
            return false;
        }
        index += count;
    }
    return true;
}

static bool
feed_one_byte_at_a_time (telegram_http_parser_t * parser, const char * response)
{
    size_t       index  = 0U;
    const size_t length = strlen(response);
    while (index < length)
    {
        if (!telegram_http_parser_feed(parser,
                                       (const uint8_t *) response + index, 1U))
        {
            return false;
        }
        index++;
    }
    return true;
}

static bool
feed_content_length_response (telegram_http_parser_t * parser, unsigned status,
                              const char * body)
{
    char      response[512];
    const int length = snprintf(response, sizeof(response),
                                "HTTP/1.1 %03u Test\r\nContent-Length: %u\r\n"
                                "\r\n%s",
                                status, (unsigned) strlen(body), body);
    assert(length > 0 && (size_t) length < sizeof(response));
    return feed_one_byte_at_a_time(parser, response);
}

static void
test_form_encoding (void)
{
    char encoded[32];
    assert(telegram_http_form_encode(encoded, sizeof(encoded),
                                     "room 1&ok=\xE2\x9C\x93"));
    assert(strcmp(encoded, "room+1%26ok%3D%E2%9C%93") == 0);
    assert(!telegram_http_form_encode(encoded, 2U, "long"));
}

static void
test_content_length_success (void)
{
    telegram_http_parser_t parser;
    telegram_http_parser_init(&parser);
    assert(feed_content_length_response(
        &parser, 200U, "{\"ok\":true,\"result\":{\"message_id\":123}}"));
    assert(telegram_http_parser_succeeded(&parser));
}

static void
test_header_optional_whitespace (void)
{
    static const char content_length_response[] =
        "HTTP/1.1 200 OK\r\nContent-Length: 11 \t\r\n\r\n"
        "{\"ok\":true}";
    static const char chunked_response[] =
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked \t\r\n\r\n"
        "B\r\n{\"ok\":true}\r\n0\r\n\r\n";
    telegram_http_parser_t parser;

    telegram_http_parser_init(&parser);
    assert(feed_all(&parser, content_length_response));
    assert(telegram_http_parser_succeeded(&parser));
    telegram_http_parser_init(&parser);
    assert(feed_all(&parser, chunked_response));
    assert(telegram_http_parser_succeeded(&parser));
}

static void
test_chunked_success (void)
{
    static const char response[] =
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        "8\r\n{\"ok\":tr\r\n"
        "B\r\nue,\"result\"\r\n"
        "8\r\n:{\"id\":1\r\n"
        "1\r\n}\r\n"
        "1\r\n}\r\n"
        "0\r\n\r\n";
    telegram_http_parser_t parser;
    telegram_http_parser_init(&parser);
    assert(feed_one_byte_at_a_time(&parser, response));
    assert(telegram_http_parser_succeeded(&parser));
}

static void
test_status_and_api_errors (void)
{
    static const char duplicate_ok[] =
        "HTTP/1.1 200 OK\r\nContent-Length: 21\r\n\r\n"
        "{\"ok\":true,\"ok\":true}";
    telegram_http_parser_t parser;
    telegram_http_parser_init(&parser);
    assert(
        feed_content_length_response(&parser, 429U, "{\"ok\":false,\"x\":0}"));
    assert(!telegram_http_parser_succeeded(&parser));
    telegram_http_parser_init(&parser);
    assert(!feed_all(&parser, duplicate_ok));
    assert(parser.failed);
}

static void
test_malformed_and_truncated (void)
{
    static const char malformed[] =
        "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n"
        "{\"ok\":truX}";
    static const char truncated[] =
        "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n"
        "{\"ok\":true}";
    telegram_http_parser_t parser;
    telegram_http_parser_init(&parser);
    assert(!feed_all(&parser, malformed));
    assert(parser.failed);
    telegram_http_parser_init(&parser);
    assert(feed_all(&parser, truncated));
    assert(!telegram_http_parser_succeeded(&parser));
}

static void
test_ambiguous_framing_and_depth (void)
{
    static const char ambiguous[] = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                                    "Transfer-Encoding: chunked\r\n\r\n{}";
    static const char too_deep[] =
        "HTTP/1.1 200 OK\r\nContent-Length: 48\r\n\r\n"
        "{\"ok\":true,\"x\":[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]}";
    telegram_http_parser_t parser;
    telegram_http_parser_init(&parser);
    assert(!feed_all(&parser, ambiguous));
    assert(parser.failed);
    telegram_http_parser_init(&parser);
    assert(!feed_all(&parser, too_deep));
    assert(parser.failed);
}

static void
test_nested_json_and_escaped_duplicate (void)
{
    telegram_http_parser_t parser;
    telegram_http_parser_init(&parser);
    const bool nested_ok = feed_content_length_response(
        &parser, 200U,
        "{\"ok\":true,\"result\":[{\"message\":{\"entities\":[1,2]}}]}");
    if (!nested_ok)
    {
        fprintf(stderr,
                "nested parser failed at body byte %u depth %u state %u\n",
                (unsigned) parser.body_received, parser.json_depth,
                parser.json_depth > 0U
                    ? parser.json_state_stack[parser.json_depth - 1U]
                    : 0U);
    }
    assert(nested_ok);
    assert(telegram_http_parser_succeeded(&parser));
    telegram_http_parser_init(&parser);
    assert(!feed_content_length_response(
        &parser, 200U, "{\"ok\":true,\"\\u006f\\u006b\":false}"));
    assert(parser.failed);
}

static void
test_bad_number_and_header_overflow (void)
{
    char                   response[TELEGRAM_HTTP_HEADER_CAPACITY + 64U];
    telegram_http_parser_t parser;
    telegram_http_parser_init(&parser);
    assert(!feed_content_length_response(&parser, 200U,
                                         "{\"ok\":true,\"result\":1.2.3}"));
    assert(parser.failed);
    memset(response, 'A', sizeof(response));
    memcpy(response, "HTTP/1.1 200 OK\r\n", 17U);
    telegram_http_parser_init(&parser);
    assert(!telegram_http_parser_feed(&parser, (const uint8_t *) response,
                                      sizeof(response)));
    assert(parser.failed);
}

static void
test_utf8_string_validation (void)
{
    telegram_http_parser_t parser;
    telegram_http_parser_init(&parser);
    assert(feed_content_length_response(
        &parser, 200U, "{\"ok\":true,\"name\":\"\xE2\x9C\x93\"}"));
    assert(telegram_http_parser_succeeded(&parser));
    telegram_http_parser_init(&parser);
    assert(!feed_content_length_response(&parser, 200U,
                                         "{\"ok\":true,\"name\":\"\xFF\"}"));
    assert(parser.failed);
    telegram_http_parser_init(&parser);
    assert(!feed_content_length_response(
        &parser, 200U, "{\"ok\":true,\"name\":\"\xC0\xAF\"}"));
    assert(parser.failed);
}

int
main (void)
{
    test_form_encoding();
    test_content_length_success();
    test_header_optional_whitespace();
    test_chunked_success();
    test_status_and_api_errors();
    test_malformed_and_truncated();
    test_ambiguous_framing_and_depth();
    test_nested_json_and_escaped_duplicate();
    test_bad_number_and_header_overflow();
    test_utf8_string_validation();
    puts("Telegram HTTP parser tests passed");
    return 0;
}
