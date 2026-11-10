/** @file storage_hash.h
 * @brief Bounded, heap-free SHA-256 state for evidence integrity, not signing.
 */
#ifndef STORAGE_HASH_H
#define STORAGE_HASH_H
#include <stddef.h>
#include <stdint.h>
typedef struct
{
    uint32_t words[8];
    uint64_t bytes;
    uint8_t  block[64];
    size_t   used;
} storage_hash_t;
void storage_hash_init(storage_hash_t * p);
void storage_hash_update(storage_hash_t * p, const uint8_t * data,
                         size_t length);
void storage_hash_finish(storage_hash_t * p, uint8_t digest[32]);
#endif
/*** end of file ***/
