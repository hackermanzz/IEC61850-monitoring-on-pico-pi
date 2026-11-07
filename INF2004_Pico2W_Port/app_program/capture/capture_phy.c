/** @file capture_phy.c
 * @brief Verify meaningful control bits without assuming reserved read values.
 */
#include "capture_phy.h"

#include <stddef.h>   /* Reject missing diagnostic storage. */
#include "mdio_phy.h" /* Single-owner Clause 22 transactions. */

#define CAPTURE_PHY_ANAR               0x0061u
#define CAPTURE_PHY_ADVERTISEMENT_MASK 0x01ffu
#define CAPTURE_PHY_BMCR               0x1200u
/* Check reset, loopback, AN-enable, power-down and isolate. Ignore restart
 * (self-clearing), speed/duplex (overridden by AN) and reserved bits 7..0.
 * Actual operating speed is still checked separately through BMSR/SCSR.
 */
#define CAPTURE_PHY_CONTROL_MASK     0xdc00u
#define CAPTURE_PHY_CONTROL_EXPECTED 0x1000u

bool
capture_phy_configure (uint8_t address, capture_phy_result_t * p_result)
{
    if (NULL == p_result)
    {
        return false;
    }
    *p_result         = (capture_phy_result_t) {0};
    p_result->p_stage = "ANAR-before";
    p_result->b_anar_before_read =
        mdio_phy_read(address, 4u, &p_result->anar_before);
    if (!p_result->b_anar_before_read)
    {
        return false;
    }
    p_result->p_stage = "ANAR-write";
    if (!mdio_phy_write(address, 4u, CAPTURE_PHY_ANAR))
    {
        return false;
    }
    p_result->p_stage     = "ANAR-read";
    p_result->b_anar_read = mdio_phy_read(address, 4u, &p_result->anar);
    if (!p_result->b_anar_read)
    {
        return false;
    }
    p_result->p_stage = "ANAR-verify";
    if (CAPTURE_PHY_ANAR != (p_result->anar & CAPTURE_PHY_ADVERTISEMENT_MASK))
    {
        return false;
    }
    p_result->p_stage = "BMCR-write";
    if (!mdio_phy_write(address, 0u, CAPTURE_PHY_BMCR))
    {
        return false;
    }
    p_result->p_stage     = "BMCR-read";
    p_result->b_bmcr_read = mdio_phy_read(address, 0u, &p_result->bmcr);
    if (!p_result->b_bmcr_read)
    {
        return false;
    }
    p_result->p_stage = "BMCR-verify";
    if (CAPTURE_PHY_CONTROL_EXPECTED
        != (p_result->bmcr & CAPTURE_PHY_CONTROL_MASK))
    {
        return false;
    }
    p_result->p_stage = "OK";
    return true;
}

/*** end of file ***/
