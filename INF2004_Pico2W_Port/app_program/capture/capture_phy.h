/** @file capture_phy.h
 * @brief Single-owner LAN8720 capture configuration and readback evidence.
 */
#ifndef CAPTURE_PHY_H
#define CAPTURE_PHY_H

#include <stdbool.h> /* Distinguish read ACK from a raw all-ones value. */
#include <stdint.h>  /* PHY register widths. */

typedef struct
{
    const char * p_stage;
    uint16_t     anar_before;
    bool         b_anar_before_read;
    uint16_t     anar;
    uint16_t     bmcr;
    bool         b_anar_read;
    bool         b_bmcr_read;
} capture_phy_result_t;

/** @brief Configure only a PHY already positively identified as LAN8720.
 * @note Caller owns initialized MDIO. No retries, reset or forced link bypass.
 * @param p_result Required diagnostic output; raw values valid only with ACK.
 */
bool capture_phy_configure(uint8_t address, capture_phy_result_t * p_result);

#endif /* CAPTURE_PHY_H */

/*** end of file ***/
