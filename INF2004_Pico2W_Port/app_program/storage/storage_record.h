/** @file storage_record.h
 * @brief Explicit little-endian, pointer-free incident file serialization.
 */
#ifndef STORAGE_RECORD_H
#define STORAGE_RECORD_H

#include "../health/evidence.h"

#define STORAGE_RECORD_HEADER (48u)
#define STORAGE_PACKET_HEADER (132u)

uint32_t storage_record_size(const evidence_record_t * p_record);
/** @brief S3 copies a bounded slice while its evidence slot remains owned. */
size_t storage_record_read(const evidence_record_t * p_record, uint32_t offset,
                           uint8_t * p_output, size_t capacity);

#endif /* STORAGE_RECORD_H */

/*** end of file ***/
