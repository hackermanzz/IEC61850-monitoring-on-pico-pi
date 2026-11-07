/** @file mdio_phy.h
 * @brief Single-owner LAN8720 management with verified read results.
 */
#ifndef MDIO_PHY_H
#define MDIO_PHY_H

#include <stdbool.h> /* Public success and identity flags. */
#include <stdint.h>  /* Exact wire-field widths. */

#define MDIO_PHY_ADDRESS_COUNT 32u

/** @brief Raw identity, including the model/revision bits without repair. */
typedef struct
{
    uint8_t  address;
    uint16_t id1;
    uint16_t id2;
    bool     b_is_lan8720;
} mdio_phy_id_t;

/** @brief Initialize GP2 MDIO released and GP3 MDC high; call once first. */
void mdio_phy_init(void);

/** @brief Read a 5-bit PHY address and 5-bit register address.
 * @param p_value Caller-owned result, changed only on successful PHY ACK.
 * @return false on missing ACK, invalid arguments or missing initialization.
 * @note Call from one owner only. This API performs no PHY writes.
 */
bool mdio_phy_read(uint8_t phy_addr, uint8_t reg_addr, uint16_t * p_value);

/** @brief Write at a slower clock; verify every released outbound one is high.
 * @return false on invalid arguments, missing init or an outbound one read low.
 * @note This is not a PHY write ACK; register readback remains mandatory.
 * @note Single owner only. Capture configures only an identified LAN8720.
 */
bool mdio_phy_write(uint8_t phy_addr, uint8_t reg_addr, uint16_t value);

/** @brief Read registers 2/3; a responsive other model is still returned.
 * @param p_identity Caller-owned result, unchanged on failure.
 * @return true only when both reads were acknowledged.
 */
bool mdio_phy_identify(uint8_t phy_addr, mdio_phy_id_t * p_identity);

#endif /* MDIO_PHY_H */

/*** end of file ***/
