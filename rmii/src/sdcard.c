#include "sdcard.h"

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#include "hardware/gpio.h"
#include "hardware/spi.h"
#include "pico/stdlib.h"

#define SD_CARD_SECTOR_SIZE 512u
#define SD_CARD_CSD_BYTES 16u
#define SD_CARD_COMMAND_PACKET_BYTES 6u
#define SD_CARD_COMMAND_FRAME_BYTES 5u
#define SD_CARD_COMMAND_PREFIX_INDEX 0u
#define SD_CARD_COMMAND_ARGUMENT_BYTE_3_INDEX 1u
#define SD_CARD_COMMAND_ARGUMENT_BYTE_2_INDEX 2u
#define SD_CARD_COMMAND_ARGUMENT_BYTE_1_INDEX 3u
#define SD_CARD_COMMAND_ARGUMENT_BYTE_0_INDEX 4u
#define SD_CARD_COMMAND_CRC_INDEX 5u
#define SD_CARD_COMMAND_FRAME_PREFIX 0x40u
#define SD_CARD_ARGUMENT_BYTE_3_SHIFT 24u
#define SD_CARD_ARGUMENT_BYTE_2_SHIFT 16u
#define SD_CARD_ARGUMENT_BYTE_1_SHIFT 8u
#define SD_CARD_BITS_PER_BYTE 8u
#define SD_CARD_FILL_BYTE 0xffu
#define SD_CARD_RESPONSE_START_BIT_MASK 0x80u
#define SD_CARD_CRC7_MSB_MASK 0x80u
#define SD_CARD_CRC7_POLYNOMIAL 0x09u
#define SD_CARD_CRC7_END_BIT 0x01u
#define SD_CARD_CRC16_MSB_MASK 0x8000u
#define SD_CARD_CRC16_POLYNOMIAL 0x1021u
#define SD_CARD_CSD_STRUCTURE_MSB 127u
#define SD_CARD_CSD_STRUCTURE_WIDTH 2u
#define SD_CARD_CSD_V2_SIZE_MSB 69u
#define SD_CARD_CSD_V2_SIZE_WIDTH 22u
#define SD_CARD_CSD_V1_READ_BLOCK_LEN_MSB 83u
#define SD_CARD_CSD_V1_READ_BLOCK_LEN_WIDTH 4u
#define SD_CARD_CSD_V1_SIZE_MSB 73u
#define SD_CARD_CSD_V1_SIZE_WIDTH 12u
#define SD_CARD_CSD_V1_SIZE_MULT_MSB 49u
#define SD_CARD_CSD_V1_SIZE_MULT_WIDTH 3u
#define SD_CARD_CSD_V2_BLOCKS_PER_UNIT 1024u
#define SD_CARD_CSD_V1_SIZE_MULT_BASE_SHIFT 2u
#define SD_CARD_PIN_RMII_RESERVED_MAX 8u
#define SD_CARD_PIN_RMII_RESERVED_EXTRA 15u
#define SD_CARD_PIN_PICO_W_INTERNAL_FIRST 23u
#define SD_CARD_PIN_PICO_W_INTERNAL_LAST 25u
#define SD_CARD_PIN_PICO_W_VSYS_SENSE 29u
#define SD_CARD_SPI0_SCK_GPIO 18u
#define SD_CARD_SPI0_MOSI_GPIO 19u
#define SD_CARD_SPI0_MISO_GPIO 16u
#define SD_CARD_R7_BYTES 4u
#define SD_CARD_OCR_BYTES 4u
#define SD_CARD_MAX_INIT_BAUD_HZ 400000u
#define SD_CARD_MAX_TRANSFER_BAUD_HZ 50000000u
#define SD_CARD_SPI_DATA_BITS SD_CARD_BITS_PER_BYTE
#define SD_CARD_POWERUP_CLOCK_BYTES 10u
#define SD_CARD_STARTUP_STABILIZATION_MS 1u
#define SD_CARD_PICO_GPIO_COUNT 30u
#define SD_CARD_CSD_STRUCTURE_V1 0u
#define SD_CARD_CSD_STRUCTURE_V2 1u
#define SD_CARD_R1_READY 0u
#define SD_CARD_CMD8_ARGUMENT 0x000001aau
#define SD_CARD_R7_VOLTAGE_INDEX 2u
#define SD_CARD_R7_CHECK_PATTERN_INDEX 3u
#define SD_CARD_R7_VOLTAGE_ACCEPTED 0x01u
#define SD_CARD_R7_CHECK_PATTERN 0xaau
#define SD_CARD_ACMD41_HIGH_CAPACITY_MASK 0x40000000u
#define SD_CARD_INITIALIZATION_RETRY_DELAY_MS 10u
#define SD_CARD_OCR_HIGH_CAPACITY_MASK 0x40u
#define SD_CARD_DATA_RESPONSE_REJECT_MASK 0x1fu
#define SD_CARD_DATA_TIMEOUT_US 250000u
#define SD_CARD_INITIALIZATION_TIMEOUT_US 1000000u
#define SD_CARD_READY_TIMEOUT_US 500000u
#define SD_CARD_R1_RESPONSE_LIMIT 10u

#define SD_CARD_CMD_GO_IDLE_STATE 0u
#define SD_CARD_CMD_SEND_IF_COND 8u
#define SD_CARD_CMD_SEND_CSD 9u
#define SD_CARD_CMD_CRC_ON_OFF 59u
#define SD_CARD_CMD_SET_BLOCKLEN 16u
#define SD_CARD_CMD_READ_SINGLE_BLOCK 17u
#define SD_CARD_CMD_WRITE_SINGLE_BLOCK 24u
#define SD_CARD_CMD_APP_CMD 55u
#define SD_CARD_CMD_READ_OCR 58u
#define SD_CARD_ACMD_SD_SEND_OP_COND 41u

#define SD_CARD_R1_IDLE 0x01u
#define SD_CARD_R1_ILLEGAL_COMMAND 0x04u
#define SD_CARD_DATA_START_TOKEN 0xfeu
#define SD_CARD_DATA_ACCEPTED 0x05u
#define SD_CARD_WRITE_START_TOKEN 0xfeu

typedef struct
{
    spi_inst_t * spi;
    uint32_t     cs_gpio;
    uint32_t     sector_count;
    uint8_t      initialized;
    uint8_t      high_capacity;
} sd_card_state_t;

static sd_card_state_t g_sd_card_state;

static uint8_t
sd_card_transfer (uint8_t value)
{
    uint8_t received = SD_CARD_FILL_BYTE;

    (void) spi_write_read_blocking(g_sd_card_state.spi, &value, &received, 1u);
    return received;
}

static void
sd_card_select (void)
{
    gpio_put(g_sd_card_state.cs_gpio, 0u);
}

static void
sd_card_deselect (void)
{
    gpio_put(g_sd_card_state.cs_gpio, 1u);
    (void) sd_card_transfer(SD_CARD_FILL_BYTE);
}

static int
sd_card_wait_ready (uint32_t timeout_us)
{
    const uint64_t deadline = time_us_64() + timeout_us;

    do
    {
        if (sd_card_transfer(SD_CARD_FILL_BYTE) == SD_CARD_FILL_BYTE)
        {
            return 1;
        }
    } while (time_us_64() < deadline);
    return 0;
}

static uint8_t
sd_card_crc7 (const uint8_t * data, size_t length)
{
    uint8_t crc   = 0u;
    size_t  index = 0u;
    uint8_t bit   = 0u;

    for (index = 0u; index < length; ++index)
    {
        uint8_t value = data[index];

        for (bit = 0u; bit < SD_CARD_BITS_PER_BYTE; ++bit)
        {
            crc <<= 1u;
            if (((value ^ crc) & SD_CARD_CRC7_MSB_MASK) != 0u)
            {
                crc ^= SD_CARD_CRC7_POLYNOMIAL;
            }
            value <<= 1u;
        }
    }
    return (uint8_t) ((crc << 1u) | SD_CARD_CRC7_END_BIT);
}

static uint8_t
sd_card_command (uint8_t command, uint32_t argument)
{
    uint8_t response = SD_CARD_FILL_BYTE;
    uint8_t packet[SD_CARD_COMMAND_PACKET_BYTES];
    uint8_t index = 0u;

    sd_card_select();
    if (!sd_card_wait_ready(SD_CARD_READY_TIMEOUT_US))
    {
        sd_card_deselect();
        return SD_CARD_FILL_BYTE;
    }

    packet[SD_CARD_COMMAND_PREFIX_INDEX] =
        (uint8_t) (SD_CARD_COMMAND_FRAME_PREFIX | command);
    packet[SD_CARD_COMMAND_ARGUMENT_BYTE_3_INDEX] =
        (uint8_t) (argument >> SD_CARD_ARGUMENT_BYTE_3_SHIFT);
    packet[SD_CARD_COMMAND_ARGUMENT_BYTE_2_INDEX] =
        (uint8_t) (argument >> SD_CARD_ARGUMENT_BYTE_2_SHIFT);
    packet[SD_CARD_COMMAND_ARGUMENT_BYTE_1_INDEX] =
        (uint8_t) (argument >> SD_CARD_ARGUMENT_BYTE_1_SHIFT);
    packet[SD_CARD_COMMAND_ARGUMENT_BYTE_0_INDEX] = (uint8_t) argument;
    packet[SD_CARD_COMMAND_CRC_INDEX] =
        sd_card_crc7(packet, SD_CARD_COMMAND_FRAME_BYTES);
    (void) spi_write_blocking(g_sd_card_state.spi, packet, sizeof(packet));

    do
    {
        response = sd_card_transfer(SD_CARD_FILL_BYTE);
        ++index;
    } while ((response & SD_CARD_RESPONSE_START_BIT_MASK) != 0u &&
             index < SD_CARD_R1_RESPONSE_LIMIT);
    return response;
}

static void
sd_card_finish_command (void)
{
    sd_card_deselect();
}

static uint16_t
sd_card_crc16 (const uint8_t * data, size_t length)
{
    uint16_t crc   = 0u;
    size_t   index = 0u;
    uint8_t  bit   = 0u;

    for (index = 0u; index < length; ++index)
    {
        crc ^= (uint16_t) data[index] << SD_CARD_BITS_PER_BYTE;
        for (bit = 0u; bit < SD_CARD_BITS_PER_BYTE; ++bit)
        {
            crc = (crc & SD_CARD_CRC16_MSB_MASK) != 0u
                      ? (uint16_t) ((crc << 1u) ^ SD_CARD_CRC16_POLYNOMIAL)
                      : (uint16_t) (crc << 1u);
        }
    }
    return crc;
}

static sd_card_status_t
sd_card_application_command (uint8_t command, uint32_t argument,
                             uint8_t * response)
{
    uint8_t app_response = SD_CARD_FILL_BYTE;

    app_response = sd_card_command(SD_CARD_CMD_APP_CMD, 0u);
    sd_card_finish_command();
    if (app_response > 1u)
    {
        return app_response == SD_CARD_FILL_BYTE ? SD_CARD_TIMEOUT
                                                 : SD_CARD_IO_ERROR;
    }
    *response = sd_card_command(command, argument);
    return *response == SD_CARD_FILL_BYTE ? SD_CARD_TIMEOUT : SD_CARD_OK;
}

static uint32_t
sd_card_extract_bits (const uint8_t * csd, uint8_t most_significant_bit,
                      uint8_t width)
{
    uint32_t value = 0u;
    uint8_t  bit   = 0u;

    for (bit = 0u; bit < width; ++bit)
    {
        const uint8_t source_bit = (uint8_t) (most_significant_bit - bit);
        const uint8_t byte_index =
            (uint8_t) (SD_CARD_CSD_BYTES - 1u -
                       source_bit / SD_CARD_BITS_PER_BYTE);

        value = (value << 1u) |
                ((uint32_t) ((csd[byte_index] >>
                              (source_bit % SD_CARD_BITS_PER_BYTE)) &
                             1u));
    }
    return value;
}

static sd_card_status_t
sd_card_read_data_block (uint8_t * buffer, size_t length)
{
    uint64_t deadline     = time_us_64() + SD_CARD_DATA_TIMEOUT_US;
    uint8_t  token        = SD_CARD_FILL_BYTE;
    uint16_t received_crc = 0u;
    uint16_t expected_crc = 0u;

    do
    {
        token = sd_card_transfer(SD_CARD_FILL_BYTE);
        if (token == SD_CARD_DATA_START_TOKEN)
        {
            break;
        }
        if (token != SD_CARD_FILL_BYTE)
        {
            return SD_CARD_IO_ERROR;
        }
    } while (time_us_64() < deadline);
    if (token != SD_CARD_DATA_START_TOKEN)
    {
        return SD_CARD_TIMEOUT;
    }

    if (spi_read_blocking(g_sd_card_state.spi, SD_CARD_FILL_BYTE, buffer,
                          length) != (int) length)
    {
        return SD_CARD_IO_ERROR;
    }
    received_crc = (uint16_t) sd_card_transfer(SD_CARD_FILL_BYTE)
                   << SD_CARD_BITS_PER_BYTE;
    received_crc |= sd_card_transfer(SD_CARD_FILL_BYTE);
    expected_crc = sd_card_crc16(buffer, length);
    return received_crc == expected_crc ? SD_CARD_OK : SD_CARD_IO_ERROR;
}

static sd_card_status_t
sd_card_get_capacity (uint32_t * sector_count)
{
    uint8_t          csd[SD_CARD_CSD_BYTES];
    uint32_t         structure         = 0u;
    uint64_t         sectors           = 0u;
    uint64_t         read_block_length = 0u;
    uint64_t         c_size            = 0u;
    uint64_t         c_size_mult       = 0u;
    sd_card_status_t status            = SD_CARD_IO_ERROR;
    uint8_t          response          = SD_CARD_FILL_BYTE;

    response = sd_card_command(SD_CARD_CMD_SEND_CSD, 0u);
    if (response != SD_CARD_R1_READY)
    {
        sd_card_finish_command();
        return response == SD_CARD_FILL_BYTE ? SD_CARD_TIMEOUT
                                             : SD_CARD_IO_ERROR;
    }
    status = sd_card_read_data_block(csd, sizeof(csd));
    sd_card_finish_command();
    if (status != SD_CARD_OK)
    {
        return status;
    }

    structure = sd_card_extract_bits(csd, SD_CARD_CSD_STRUCTURE_MSB,
                                     SD_CARD_CSD_STRUCTURE_WIDTH);
    if (structure == SD_CARD_CSD_STRUCTURE_V2)
    {
        c_size  = sd_card_extract_bits(csd, SD_CARD_CSD_V2_SIZE_MSB,
                                       SD_CARD_CSD_V2_SIZE_WIDTH);
        sectors = (c_size + 1u) * SD_CARD_CSD_V2_BLOCKS_PER_UNIT;
    }
    else if (structure == SD_CARD_CSD_STRUCTURE_V1)
    {
        read_block_length = (uint64_t) 1u << sd_card_extract_bits(
                                csd, SD_CARD_CSD_V1_READ_BLOCK_LEN_MSB,
                                SD_CARD_CSD_V1_READ_BLOCK_LEN_WIDTH);
        c_size            = sd_card_extract_bits(csd, SD_CARD_CSD_V1_SIZE_MSB,
                                                 SD_CARD_CSD_V1_SIZE_WIDTH);
        c_size_mult = sd_card_extract_bits(csd, SD_CARD_CSD_V1_SIZE_MULT_MSB,
                                           SD_CARD_CSD_V1_SIZE_MULT_WIDTH);
        sectors = ((c_size + 1u) *
                   ((uint64_t) 1u
                    << (c_size_mult + SD_CARD_CSD_V1_SIZE_MULT_BASE_SHIFT)) *
                   read_block_length) /
                  SD_CARD_SECTOR_SIZE;
    }
    else
    {
        return SD_CARD_UNSUPPORTED;
    }

    if (sectors == 0u || sectors > UINT32_MAX)
    {
        return SD_CARD_UNSUPPORTED;
    }
    *sector_count = (uint32_t) sectors;
    return SD_CARD_OK;
}

static int
sd_card_pin_is_rmii_reserved (uint32_t pin)
{
    return pin <= SD_CARD_PIN_RMII_RESERVED_MAX ||
           pin == SD_CARD_PIN_RMII_RESERVED_EXTRA;
}

static int
sd_card_pin_is_pico_w_internal (uint32_t pin)
{
    /* Pico W uses these GPIOs for CYW43 control and VSYS sensing. */
    return (pin >= SD_CARD_PIN_PICO_W_INTERNAL_FIRST &&
            pin <= SD_CARD_PIN_PICO_W_INTERNAL_LAST) ||
           pin == SD_CARD_PIN_PICO_W_VSYS_SENSE;
}

static int
sd_card_pins_are_valid (const sd_card_config_t * config)
{
    uint32_t spi_index     = 0u;
    uint32_t max_pin       = 0u;
    int      mapping_valid = 0;

    if (config->spi != spi0 && config->spi != spi1)
    {
        return 0;
    }
    spi_index = (uint32_t) spi_get_index(config->spi);
#if defined(NUM_BANK0_GPIOS)
    max_pin = NUM_BANK0_GPIOS;
#else
    max_pin = SD_CARD_PICO_GPIO_COUNT;
#endif
    if (spi_index > 1u || config->sck_gpio >= max_pin ||
        config->mosi_gpio >= max_pin || config->miso_gpio >= max_pin ||
        config->cs_gpio >= max_pin)
    {
        return 0;
    }
    if (config->sck_gpio == config->mosi_gpio ||
        config->sck_gpio == config->miso_gpio ||
        config->sck_gpio == config->cs_gpio ||
        config->mosi_gpio == config->miso_gpio ||
        config->mosi_gpio == config->cs_gpio ||
        config->miso_gpio == config->cs_gpio)
    {
        return 0;
    }
    if (sd_card_pin_is_rmii_reserved(config->sck_gpio) ||
        sd_card_pin_is_rmii_reserved(config->mosi_gpio) ||
        sd_card_pin_is_rmii_reserved(config->miso_gpio) ||
        sd_card_pin_is_rmii_reserved(config->cs_gpio) ||
        sd_card_pin_is_pico_w_internal(config->cs_gpio))
    {
        return 0;
    }

    if (spi_index == 0u)
    {
        mapping_valid = config->sck_gpio == SD_CARD_SPI0_SCK_GPIO &&
                        config->mosi_gpio == SD_CARD_SPI0_MOSI_GPIO &&
                        config->miso_gpio == SD_CARD_SPI0_MISO_GPIO;
    }
    return mapping_valid;
}

static void
sd_card_configure_bus (const sd_card_config_t * config)
{
    g_sd_card_state.spi     = config->spi;
    g_sd_card_state.cs_gpio = config->cs_gpio;
    (void) spi_init(g_sd_card_state.spi, config->init_baud_hz);
    spi_set_format(g_sd_card_state.spi, SD_CARD_SPI_DATA_BITS, SPI_CPOL_0,
                   SPI_CPHA_0, SPI_MSB_FIRST);
    gpio_set_function(config->sck_gpio, GPIO_FUNC_SPI);
    gpio_set_function(config->mosi_gpio, GPIO_FUNC_SPI);
    gpio_set_function(config->miso_gpio, GPIO_FUNC_SPI);
    gpio_init(config->cs_gpio);
    gpio_set_dir(config->cs_gpio, GPIO_OUT);
    gpio_put(config->cs_gpio, 1u);
    sleep_ms(SD_CARD_STARTUP_STABILIZATION_MS);
    for (uint8_t index = 0u; index < SD_CARD_POWERUP_CLOCK_BYTES; ++index)
    {
        (void) sd_card_transfer(SD_CARD_FILL_BYTE);
    }
}

static sd_card_status_t
sd_card_enter_idle_state (void)
{
    uint8_t  response = SD_CARD_FILL_BYTE;
    uint64_t deadline = time_us_64() + SD_CARD_INITIALIZATION_TIMEOUT_US;

    do
    {
        response = sd_card_command(SD_CARD_CMD_GO_IDLE_STATE, 0u);
        sd_card_finish_command();
        if (response == SD_CARD_R1_IDLE)
        {
            break;
        }
    } while (time_us_64() < deadline);
    if (response != SD_CARD_R1_IDLE)
    {
        return response == SD_CARD_FILL_BYTE ? SD_CARD_TIMEOUT
                                             : SD_CARD_IO_ERROR;
    }
    return SD_CARD_OK;
}

static sd_card_status_t
sd_card_check_interface_condition (int * version_two)
{
    uint8_t response = SD_CARD_FILL_BYTE;
    uint8_t r7[SD_CARD_R7_BYTES];
    uint8_t index = 0u;

    response = sd_card_command(SD_CARD_CMD_SEND_IF_COND, SD_CARD_CMD8_ARGUMENT);
    if (response == SD_CARD_R1_IDLE)
    {
        for (index = 0u; index < sizeof(r7); ++index)
        {
            r7[index] = sd_card_transfer(SD_CARD_FILL_BYTE);
        }
        *version_two =
            r7[SD_CARD_R7_VOLTAGE_INDEX] == SD_CARD_R7_VOLTAGE_ACCEPTED &&
            r7[SD_CARD_R7_CHECK_PATTERN_INDEX] == SD_CARD_R7_CHECK_PATTERN;
        sd_card_finish_command();
        if (*version_two == 0)
        {
            return SD_CARD_UNSUPPORTED;
        }
    }
    else if (response != SD_CARD_FILL_BYTE &&
             (response & SD_CARD_R1_ILLEGAL_COMMAND) != 0u)
    {
        *version_two = 0;
        sd_card_finish_command();
    }
    else
    {
        sd_card_finish_command();
        return response == SD_CARD_FILL_BYTE ? SD_CARD_TIMEOUT
                                             : SD_CARD_IO_ERROR;
    }
    return SD_CARD_OK;
}

static sd_card_status_t
sd_card_wait_operating_condition (int version_two)
{
    uint8_t  response       = SD_CARD_FILL_BYTE;
    uint64_t deadline       = time_us_64() + SD_CARD_INITIALIZATION_TIMEOUT_US;
    sd_card_status_t status = SD_CARD_IO_ERROR;

    do
    {
        status = sd_card_application_command(
            SD_CARD_ACMD_SD_SEND_OP_COND,
            version_two ? SD_CARD_ACMD41_HIGH_CAPACITY_MASK : 0u, &response);
        sd_card_finish_command();
        if (status != SD_CARD_OK)
        {
            return status;
        }
        if (response == 0u)
        {
            break;
        }
        if (response != SD_CARD_R1_IDLE)
        {
            return SD_CARD_IO_ERROR;
        }
        sleep_ms(SD_CARD_INITIALIZATION_RETRY_DELAY_MS);
    } while (time_us_64() < deadline);
    if (response != 0u)
    {
        return SD_CARD_TIMEOUT;
    }
    return SD_CARD_OK;
}

static sd_card_status_t
sd_card_enable_crc (void)
{
    uint8_t response = SD_CARD_FILL_BYTE;

    response = sd_card_command(SD_CARD_CMD_CRC_ON_OFF, 1u);
    sd_card_finish_command();
    if (response != 0u)
    {
        if (response == SD_CARD_FILL_BYTE)
        {
            return SD_CARD_TIMEOUT;
        }
        return (response & SD_CARD_R1_ILLEGAL_COMMAND) != 0u
                   ? SD_CARD_UNSUPPORTED
                   : SD_CARD_IO_ERROR;
    }
    return SD_CARD_OK;
}

static sd_card_status_t
sd_card_configure_addressing (void)
{
    uint8_t response = SD_CARD_FILL_BYTE;
    uint8_t ocr[SD_CARD_OCR_BYTES];
    uint8_t index = 0u;

    response = sd_card_command(SD_CARD_CMD_READ_OCR, 0u);
    if (response != 0u)
    {
        sd_card_finish_command();
        return response == SD_CARD_FILL_BYTE ? SD_CARD_TIMEOUT
                                             : SD_CARD_IO_ERROR;
    }
    for (index = 0u; index < sizeof(ocr); ++index)
    {
        ocr[index] = sd_card_transfer(SD_CARD_FILL_BYTE);
    }
    sd_card_finish_command();
    g_sd_card_state.high_capacity =
        (uint8_t) ((ocr[0] & SD_CARD_OCR_HIGH_CAPACITY_MASK) != 0u);
    if (!g_sd_card_state.high_capacity)
    {
        response =
            sd_card_command(SD_CARD_CMD_SET_BLOCKLEN, SD_CARD_SECTOR_SIZE);
        sd_card_finish_command();
        if (response != 0u)
        {
            return response == SD_CARD_FILL_BYTE ? SD_CARD_TIMEOUT
                                                 : SD_CARD_IO_ERROR;
        }
    }
    return SD_CARD_OK;
}

sd_card_status_t
sd_card_init (const sd_card_config_t * config)
{
    int              version_two = 0;
    sd_card_status_t status      = SD_CARD_IO_ERROR;

    sd_card_deinit();
    if (config == NULL || config->init_baud_hz == 0u ||
        config->init_baud_hz > SD_CARD_MAX_INIT_BAUD_HZ ||
        config->transfer_baud_hz == 0u ||
        config->transfer_baud_hz > SD_CARD_MAX_TRANSFER_BAUD_HZ ||
        !sd_card_pins_are_valid(config))
    {
        return SD_CARD_INVALID_ARGUMENT;
    }
    sd_card_configure_bus(config);
    status = sd_card_enter_idle_state();
    if (status == SD_CARD_OK)
    {
        status = sd_card_check_interface_condition(&version_two);
    }
    if (status == SD_CARD_OK)
    {
        status = sd_card_wait_operating_condition(version_two);
    }
    if (status == SD_CARD_OK)
    {
        status = sd_card_enable_crc();
    }
    if (status == SD_CARD_OK)
    {
        status = sd_card_configure_addressing();
    }
    if (status == SD_CARD_OK)
    {
        (void) spi_set_baudrate(g_sd_card_state.spi, config->transfer_baud_hz);
        status = sd_card_get_capacity(&g_sd_card_state.sector_count);
    }
    if (status != SD_CARD_OK)
    {
        sd_card_deinit();
        return status;
    }
    g_sd_card_state.initialized = 1u;
    return SD_CARD_OK;
}

sd_card_status_t
sd_card_read_sector (uint32_t lba, uint8_t * buffer)
{
    uint32_t         argument = 0u;
    uint8_t          response = SD_CARD_FILL_BYTE;
    sd_card_status_t status   = SD_CARD_IO_ERROR;

    if (buffer == NULL)
    {
        return SD_CARD_INVALID_ARGUMENT;
    }
    if (g_sd_card_state.initialized == 0u)
    {
        return SD_CARD_NOT_READY;
    }
    if (lba >= g_sd_card_state.sector_count)
    {
        return SD_CARD_INVALID_ARGUMENT;
    }
    if (g_sd_card_state.high_capacity != 0u)
    {
        argument = lba;
    }
    else
    {
        if (lba > UINT32_MAX / SD_CARD_SECTOR_SIZE)
        {
            return SD_CARD_INVALID_ARGUMENT;
        }
        argument = lba * SD_CARD_SECTOR_SIZE;
    }

    response = sd_card_command(SD_CARD_CMD_READ_SINGLE_BLOCK, argument);
    if (response == 0u)
    {
        status = sd_card_read_data_block(buffer, SD_CARD_SECTOR_SIZE);
    }
    else
    {
        status =
            response == SD_CARD_FILL_BYTE ? SD_CARD_TIMEOUT : SD_CARD_IO_ERROR;
    }
    sd_card_finish_command();
    return status;
}

sd_card_status_t
sd_card_write_sector (uint32_t lba, const uint8_t * buffer)
{
    uint32_t         argument          = 0u;
    uint8_t          response          = SD_CARD_FILL_BYTE;
    uint8_t          data_response     = SD_CARD_FILL_BYTE;
    uint16_t         crc               = 0u;
    uint64_t         response_deadline = 0u;
    sd_card_status_t status            = SD_CARD_IO_ERROR;

    if (buffer == NULL)
    {
        return SD_CARD_INVALID_ARGUMENT;
    }
    if (g_sd_card_state.initialized == 0u)
    {
        return SD_CARD_NOT_READY;
    }
    if (lba >= g_sd_card_state.sector_count)
    {
        return SD_CARD_INVALID_ARGUMENT;
    }
    if (g_sd_card_state.high_capacity != 0u)
    {
        argument = lba;
    }
    else
    {
        if (lba > UINT32_MAX / SD_CARD_SECTOR_SIZE)
        {
            return SD_CARD_INVALID_ARGUMENT;
        }
        argument = lba * SD_CARD_SECTOR_SIZE;
    }

    response = sd_card_command(SD_CARD_CMD_WRITE_SINGLE_BLOCK, argument);
    if (response != 0u)
    {
        status =
            response == SD_CARD_FILL_BYTE ? SD_CARD_TIMEOUT : SD_CARD_IO_ERROR;
        sd_card_finish_command();
        return status;
    }
    (void) sd_card_transfer(SD_CARD_FILL_BYTE);
    (void) sd_card_transfer(SD_CARD_WRITE_START_TOKEN);
    (void) spi_write_blocking(g_sd_card_state.spi, buffer, SD_CARD_SECTOR_SIZE);
    crc = sd_card_crc16(buffer, SD_CARD_SECTOR_SIZE);
    (void) sd_card_transfer((uint8_t) (crc >> SD_CARD_BITS_PER_BYTE));
    (void) sd_card_transfer((uint8_t) crc);
    response_deadline = time_us_64() + SD_CARD_DATA_TIMEOUT_US;
    do
    {
        data_response = sd_card_transfer(SD_CARD_FILL_BYTE);
    } while (data_response == SD_CARD_FILL_BYTE &&
             time_us_64() < response_deadline);
    if (data_response == SD_CARD_FILL_BYTE)
    {
        sd_card_finish_command();
        return SD_CARD_TIMEOUT;
    }
    data_response &= SD_CARD_DATA_RESPONSE_REJECT_MASK;
    if (data_response != SD_CARD_DATA_ACCEPTED)
    {
        sd_card_finish_command();
        return SD_CARD_IO_ERROR;
    }
    status = sd_card_wait_ready(SD_CARD_DATA_TIMEOUT_US) ? SD_CARD_OK
                                                         : SD_CARD_TIMEOUT;
    sd_card_finish_command();
    return status;
}

sd_card_status_t
sd_card_sync (void)
{
    sd_card_status_t status = SD_CARD_OK;

    if (g_sd_card_state.initialized == 0u)
    {
        return SD_CARD_NOT_READY;
    }
    sd_card_select();
    if (!sd_card_wait_ready(SD_CARD_READY_TIMEOUT_US))
    {
        status = SD_CARD_TIMEOUT;
    }
    sd_card_finish_command();
    return status;
}

sd_card_status_t
sd_card_sector_count (uint32_t * count)
{
    if (count == NULL)
    {
        return SD_CARD_INVALID_ARGUMENT;
    }
    if (g_sd_card_state.initialized == 0u)
    {
        return SD_CARD_NOT_READY;
    }
    *count = g_sd_card_state.sector_count;
    return SD_CARD_OK;
}

bool
sd_card_is_ready (void)
{
    return g_sd_card_state.initialized != 0u;
}

void
sd_card_deinit (void)
{
    if (g_sd_card_state.spi != NULL)
    {
        gpio_put(g_sd_card_state.cs_gpio, 1u);
        spi_deinit(g_sd_card_state.spi);
    }
    g_sd_card_state.initialized   = 0u;
    g_sd_card_state.high_capacity = 0u;
    g_sd_card_state.sector_count  = 0u;
    g_sd_card_state.spi           = NULL;
    g_sd_card_state.cs_gpio       = 0u;
}
