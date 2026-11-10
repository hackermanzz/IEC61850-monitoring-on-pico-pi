/** @file storage.h
 * @brief Copied bounded chunks to S1,matched durable completion back to S3.
 */
#ifndef STORAGE_H
#define STORAGE_H

#include <stdbool.h>
#include <stdint.h>

#define STORAGE_CHUNK_BYTES (256u)
#define STORAGE_START       (1u)
#define STORAGE_END         (2u)

typedef struct
{
    uint32_t slot;
    uint32_t incident_id;
    uint32_t offset;
    uint32_t total;
    uint16_t length;
    uint16_t flags;
    uint8_t  data[STORAGE_CHUNK_BYTES];
} storage_chunk_t;

typedef struct
{
    uint32_t slot;
    uint32_t incident_id;
    uint32_t success;
} storage_ack_t;

bool storage_init(void);
bool storage_start(void);
/** @brief S3 owner only: one copied chunk per call,never wait for SD. */
void storage_poll(void);
/** @brief S1 owner only: bounded service step,also used by host simulation. */
void storage_worker_step(void);
/** @brief S3 console owner only; S1 never prints or uses libc/TLS state. */
void storage_report(void);

#endif /* STORAGE_H */

/*** end of file ***/
