/*
 * app_messages.h
 * Message and block layouts shared between IS18 µT-Kernel tasks.
 *
 *   Capture (core 1) --[mpf_frames block via mbx_frames]--> Stream Analysis
 *   Stream Analysis  --[mbf_pred event]-------------------> Incident Manager
 *   Stream Analysis  --[mpf_evidence block, pointer in event]--> Incident Mgr
 *
 * Ownership rule: a block has exactly one owner at a time. The sender stops
 * touching a block as soon as it posts it; the receiver releases it.
 */
#ifndef APP_MESSAGES_H
#define APP_MESSAGES_H

#include <tk/tkernel.h>
#include <stdbool.h>
#include <stdint.h>

#include "analyzer.h"
#include "app_config.h"

/* One captured Ethernet frame. Lives in the fixed memory pool mpf_frames.
 * T_MSG must be the first member because the mailbox links blocks through
 * it. The frame is decoded straight into data[], so nothing is copied. */
typedef struct
{
    T_MSG    header;
    uint32_t seq;          /* capture sequence: +1 per GOOSE/SV frame seen */
    uint64_t timestamp_us; /* CRS_DV falling edge, taken in the ISR */
    uint16_t length;       /* frame length without FCS */
    uint16_t reserved;
    uint8_t  data[IS18_FRAME_DATA_BYTES];
} is18_frame_block_t;

/* Kinds of event sent to the Incident Manager. */
typedef enum
{
    IS18_EVENT_PREDICTION = 1, /* a scored 4 frame window */
    IS18_EVENT_STREAM_RESET,   /* drop this stream's previous vote */
    IS18_EVENT_CAPTURE_GAP,    /* frames were lost before analysis */
    IS18_EVENT_OVERLOAD        /* Capture Overload Warning (FR8) */
} is18_event_kind_t;

/* Evidence for a malicious looking window: metadata of all four frames and
 * the bytes of the newest one. Lives in mpf_evidence; the Incident Manager
 * owns it after receiving the event and must release it. */
typedef struct
{
    analyzer_packet_metadata_t packets[ANALYZER_BATCH_FRAME_COUNT];
    uint16_t                   newest_length;
    uint16_t                   reserved;
    uint8_t                    newest_frame[ANALYZER_MAXIMUM_FRAME_LENGTH];
} is18_evidence_t;

/* Small fixed size event, copied through the message buffer mbf_pred. */
typedef struct
{
    uint8_t           kind;        /* is18_event_kind_t */
    uint8_t           protocol;    /* analyzer_protocol_t */
    uint8_t           label;       /* model label with its trained threshold */
    uint8_t           flags;
    uint16_t          appid;
    uint16_t          reserved;
    uint32_t          stream_key;
    float             probability;
    uint32_t          first_seq;   /* window range, or lost range for gaps */
    uint32_t          last_seq;
    uint64_t          timestamp_us;
    is18_evidence_t * evidence;    /* NULL when no evidence was attached */
} is18_event_t;

/* Kernel object ids, created in app_main.c. */
extern ID g_is18_mpf_frames;
extern ID g_is18_mbx_frames;
extern ID g_is18_mbf_pred;
extern ID g_is18_mpf_evidence;

#endif /* APP_MESSAGES_H */
