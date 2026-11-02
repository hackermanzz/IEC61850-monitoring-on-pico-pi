
#ifndef CAPTURE_FRAME_H
#define CAPTURE_FRAME_H

#include <stdint.h>
#include <stddef.h>
#ifndef PROHIBIT_DEF_SIZE_T
#define PROHIBIT_DEF_SIZE_T 1
#endif
#include <tk/tkernel.h>

#define CAPTURE_FRAME_CAPACITY 1518u


typedef struct {
    T_MSG header;
    uint32_t seqNum;
    uint64_t timestamp_us;
    uint16_t valid_byte_count;
    uint8_t frame_data[CAPTURE_FRAME_CAPACITY]; // Max size of 1518 per packet.
} capture_frame_t ;

_Static_assert(offsetof(capture_frame_t, header) == 0,
               "Mailbox linkage must be the first member");
_Static_assert(CAPTURE_FRAME_CAPACITY <= UINT16_MAX,
               "Frame length must fit valid_byte_count");


#endif
