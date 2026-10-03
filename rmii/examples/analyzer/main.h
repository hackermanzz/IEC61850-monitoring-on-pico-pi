/*
 * Copyright (c) 2021 Sandeep Mistry
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Configuration constants for the Pico analyzer application entry point.
 */

#ifndef PICO_IEC61850_ANALYZER_MAIN_H
#define PICO_IEC61850_ANALYZER_MAIN_H

#include <stdint.h>

#define RMII_TRANSMIT_PIN_START (0u)
#define RMII_MANAGEMENT_PIN_START (4u)
#define RMII_RECEIVE_PIN_START (6u)
#define CLASS_LED_PIN (15u)
#define SYSTEM_CLOCK_KHZ (50000u)
#define MICROSECONDS_PER_MILLISECOND (1000u)
#define PREDICTION_LOG_INTERVAL (1000u)
#define MALICIOUS_LABEL (1u)
#define BENIGN_LABEL (2u)
#define PHY_SPEED_SHIFT (2u)
#define PHY_SPEED_MASK (7u)
#define PHY_SPEED_10_HALF (1u)
#define PHY_SPEED_10_FULL (5u)
#define PHY_SPEED_100_HALF (2u)
#define PHY_SPEED_100_FULL (6u)
#define MAC_ADDRESS_BYTE_0 (0u)
#define MAC_ADDRESS_BYTE_1 (1u)
#define MAC_ADDRESS_BYTE_2 (2u)
#define MAC_ADDRESS_BYTE_3 (3u)
#define MAC_ADDRESS_BYTE_4 (4u)
#define MAC_ADDRESS_BYTE_5 (5u)
#define MAXIMUM_FRAME_LENGTH (1518u)
#define MALICIOUS_PROBABILITY_GATE (0.65f)
#define MODEL_AGREEMENT_WINDOW_US (UINT64_C(1000000))
#define SUMMARY_INTERVAL_MS (10000u)
#define USB_STARTUP_DELAY_MS (1200u)
#define RETRY_DELAY_MS (2000u)
#define IDLE_DELAY_US (100u)
#define WATCHDOG_TIMEOUT_MS (8000u)

int main (void);

#endif
