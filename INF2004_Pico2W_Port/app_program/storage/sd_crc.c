/** @file sd_crc.c
 * @brief CRC7 with end bit and CRC16-CCITT with initial value zero.
 */
#include "sd_crc.h"

uint8_t
sd_crc7 (const uint8_t * p_bytes, size_t length)
{
    uint8_t crc = 0u;
    for (size_t index = 0u; length > index; index++)
    {
        uint8_t data = p_bytes[index];
        for (uint32_t bit = 0u; 8u > bit; bit++)
        {
            crc <<= 1u;
            if (0u != ((data ^ crc) & 0x80u))
            {
                crc ^= 0x09u;
            }
            data <<= 1u;
        }
    }
    return (uint8_t) ((crc << 1u) | 1u);
}

uint16_t
sd_crc16 (const uint8_t * p_bytes, size_t length)
{
    uint16_t crc = 0u;
    for (size_t index = 0u; length > index; index++)
    {
        crc ^= (uint16_t) p_bytes[index] << 8u;
        for (uint32_t bit = 0u; 8u > bit; bit++)
        {
            crc = (uint16_t) ((crc << 1u)
                              ^ ((0u != (crc & 0x8000u)) ? 0x1021u : 0u));
        }
    }
    return crc;
}

/*** end of file ***/
