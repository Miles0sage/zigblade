/**
 * @file zigbee_injector.h
 * @brief Zigbee / IEEE 802.15.4 frame injection engine.
 */

#ifndef ZIGBLADE_ZIGBEE_INJECTOR_H
#define ZIGBLADE_ZIGBEE_INJECTOR_H

#include <stdint.h>
#include "esp_err.h"
#include "zigbee_sniffer.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize the injector subsystem.
 *
 * Must be called after zigblade_radio_init().
 *
 * @return ESP_OK on success.
 */
esp_err_t zigbee_injector_init(void);

/**
 * @brief Inject a raw IEEE 802.15.4 frame.
 *
 * The caller must construct the complete MAC frame (FCF, sequence
 * number, addressing, payload). FCS is appended by hardware.
 *
 * @param frame  Raw MAC frame bytes.
 * @param len    Frame length (max 125 bytes without FCS).
 * @return ESP_OK on success.
 */
esp_err_t zigbee_inject_raw(uint8_t *frame, uint8_t len);

/**
 * @brief Inject a forged Zigbee beacon frame.
 *
 * Constructs a valid beacon frame with the specified PAN ID on the
 * given channel, advertising an open network.
 *
 * @param panid    PAN ID to advertise.
 * @param channel  Channel to transmit on (radio is switched temporarily).
 * @return ESP_OK on success.
 */
esp_err_t zigbee_inject_beacon(uint16_t panid, uint8_t channel);

/**
 * @brief Replay a previously captured packet.
 *
 * Retransmits the raw frame from a captured_packet_t, optionally
 * incrementing the sequence number to avoid duplicate detection.
 *
 * @param pkt  Captured packet to replay.
 * @return ESP_OK on success.
 */
esp_err_t zigbee_inject_replay(const captured_packet_t *pkt);

/**
 * @brief Inject a data frame with spoofed source/destination.
 *
 * Constructs an IEEE 802.15.4 data frame with intra-PAN addressing
 * and the provided payload. Caller sets PAN ID via
 * zigblade_radio_set_panid() before calling.
 *
 * @param dst_short  Destination short address.
 * @param src_short  Spoofed source short address.
 * @param panid      PAN ID for the frame.
 * @param payload    Payload bytes.
 * @param len        Payload length.
 * @return ESP_OK on success.
 */
esp_err_t zigbee_inject_data(uint16_t dst_short,
                             uint16_t src_short,
                             uint16_t panid,
                             const uint8_t *payload,
                             uint8_t len);

/**
 * @brief Send a disassociation notification to a target device.
 *
 * Constructs a MAC command frame (Disassociation Notification,
 * command ID 0x03) directed at the target short address. This can
 * force the target to leave the network.
 *
 * @param target_short  Target device short address.
 * @param panid         Target PAN ID.
 * @param coord_short   Coordinator address to spoof as source.
 * @return ESP_OK on success.
 */
esp_err_t zigbee_inject_disassoc(uint16_t target_short,
                                 uint16_t panid,
                                 uint16_t coord_short);

/**
 * @brief Get the running count of injected frames.
 *
 * @return Number of frames injected since init.
 */
uint32_t zigbee_injector_get_tx_count(void);

#ifdef __cplusplus
}
#endif

#endif /* ZIGBLADE_ZIGBEE_INJECTOR_H */
