/**
 * @file ieee802154_hal.h
 * @brief IEEE 802.15.4 Hardware Abstraction Layer for ESP32-H2
 *
 * Provides a clean interface to the ESP32-H2's native 802.15.4 radio,
 * wrapping esp_ieee802154 APIs for promiscuous receive, transmit, and
 * address/PAN configuration used by ZigBlade scanner/sniffer/injector.
 */

#ifndef ZIGBLADE_IEEE802154_HAL_H
#define ZIGBLADE_IEEE802154_HAL_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum 802.15.4 PHY frame length (excluding FCS added by HW) */
#define ZIGBLADE_MAX_FRAME_LEN    127

/** 802.15.4 channel range */
#define ZIGBLADE_CHANNEL_MIN      11
#define ZIGBLADE_CHANNEL_MAX      26
#define ZIGBLADE_NUM_CHANNELS     (ZIGBLADE_CHANNEL_MAX - ZIGBLADE_CHANNEL_MIN + 1)

/** Default PAN ID used in promiscuous mode */
#define ZIGBLADE_PROMISC_PANID    0xFFFF

/**
 * @brief Callback type for received frames.
 *
 * @param frame  Pointer to the raw 802.15.4 frame (MAC header + payload).
 * @param len    Length of the frame in bytes.
 * @param rssi   Received signal strength indicator in dBm.
 */
typedef void (*zigblade_rx_callback_t)(uint8_t *frame, uint8_t len, int8_t rssi);

/**
 * @brief Initialize the 802.15.4 radio hardware.
 *
 * Enables the radio peripheral, sets promiscuous mode, and configures
 * default channel 11. Must be called before any other radio function.
 *
 * @return ESP_OK on success, or an error code.
 */
esp_err_t zigblade_radio_init(void);

/**
 * @brief Deinitialize the radio and release resources.
 *
 * @return ESP_OK on success.
 */
esp_err_t zigblade_radio_deinit(void);

/**
 * @brief Set the active channel.
 *
 * @param channel  Channel number (11-26).
 * @return ESP_OK on success, ESP_ERR_INVALID_ARG if channel out of range.
 */
esp_err_t zigblade_radio_set_channel(uint8_t channel);

/**
 * @brief Get the current channel.
 *
 * @return Current channel number.
 */
uint8_t zigblade_radio_get_channel(void);

/**
 * @brief Start receiving in promiscuous mode.
 *
 * All received frames (regardless of destination address) will be
 * delivered via the registered RX callback.
 *
 * @return ESP_OK on success.
 */
esp_err_t zigblade_radio_start_receive(void);

/**
 * @brief Stop receiving.
 *
 * @return ESP_OK on success.
 */
esp_err_t zigblade_radio_stop_receive(void);

/**
 * @brief Transmit a raw 802.15.4 frame.
 *
 * The frame must include the MAC header but NOT the FCS — hardware
 * appends the 2-byte FCS automatically.
 *
 * The first byte of `frame` must be the PHY length byte (length of
 * MPDU including the 2-byte FCS that HW will append).
 *
 * @param frame  Raw frame buffer. frame[0] = PHY length.
 * @param len    Buffer length (PHY length byte + MPDU bytes, without FCS).
 * @return ESP_OK on success, ESP_ERR_INVALID_ARG if len exceeds maximum.
 */
esp_err_t zigblade_radio_transmit(uint8_t *frame, uint8_t len);

/**
 * @brief Set PAN ID for filtering (or 0xFFFF for promiscuous).
 *
 * @param panid  16-bit PAN identifier.
 * @return ESP_OK on success.
 */
esp_err_t zigblade_radio_set_panid(uint16_t panid);

/**
 * @brief Set 16-bit short address.
 *
 * @param addr  Short address.
 * @return ESP_OK on success.
 */
esp_err_t zigblade_radio_set_short_addr(uint16_t addr);

/**
 * @brief Set 64-bit extended (IEEE) address.
 *
 * @param addr  Pointer to 8-byte extended address (little-endian).
 * @return ESP_OK on success, ESP_ERR_INVALID_ARG if addr is NULL.
 */
esp_err_t zigblade_radio_set_ext_addr(uint8_t *addr);

/**
 * @brief Register a callback for received frames.
 *
 * Only one callback can be registered at a time; calling this again
 * replaces the previous callback. Pass NULL to unregister.
 *
 * @param cb  Callback function, or NULL to clear.
 * @return ESP_OK on success.
 */
esp_err_t zigblade_radio_register_rx_callback(zigblade_rx_callback_t cb);

/**
 * @brief Check if the radio is currently receiving.
 *
 * @return true if in receive mode.
 */
bool zigblade_radio_is_receiving(void);

#ifdef __cplusplus
}
#endif

#endif /* ZIGBLADE_IEEE802154_HAL_H */
