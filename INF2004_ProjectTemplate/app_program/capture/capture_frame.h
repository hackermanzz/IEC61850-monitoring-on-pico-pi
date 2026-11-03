/** @file capture_frame.h
 *
 * @brief The capture frame container that the capture producer task sends
 * to the analysis consumer through a micro T-Kernel mailbox.
 */
#ifndef CAPTURE_FRAME_H
#define CAPTURE_FRAME_H

#include <stddef.h>
#include <stdint.h>

// NOTE: <stddef.h> already defines size_t, so the kernel headers must not.
//
#ifndef PROHIBIT_DEF_SIZE_T
#define PROHIBIT_DEF_SIZE_T 1
#endif
#include <tk/tkernel.h>

// Largest frame stored, without the FCS.
//
#define CAPTURE_FRAME_CAPACITY (1518u)

typedef struct
{
    T_MSG    header;           // Mailbox link; must be the first member.
    uint32_t sequence_number;  // Capture order; a gap means lost frames.
    uint64_t timestamp_us;     // Frame end time from the CRS_DV interrupt.
    uint16_t valid_byte_count; // Number of valid bytes in frame_data.
    uint8_t  frame_data[CAPTURE_FRAME_CAPACITY];
} capture_frame_t;

_Static_assert(0u == offsetof(capture_frame_t, header),
               "Mailbox linkage must be the first member");
_Static_assert(CAPTURE_FRAME_CAPACITY <= UINT16_MAX,
               "Frame length must fit valid_byte_count");

#endif /* CAPTURE_FRAME_H */

/*** end of file ***/
