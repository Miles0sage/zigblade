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

/* ── Frame-counter-aware replay (Weakness 2 fix) ────────────────── */

/** Maximum devices whose frame counters we can track simultaneously. */
#define INJECTOR_FC_TRACK_MAX   32

/** Tracked frame counter entry for a device */
typedef struct {
    uint16_t short_addr;             /**< Device short address            */
    uint8_t  ext_addr[8];           /**< Device IEEE address (for nonce) */
    bool     ext_addr_valid;         /**< ext_addr is populated          */
    uint32_t last_frame_counter;     /**< Highest frame counter seen     */
    uint16_t panid;                  /**< PAN ID of the device           */
} fc_track_entry_t;

/**
 * @brief Update the tracked frame counter for a device.
 *
 * Called automatically by the sniffer callback when integrated, or
 * manually when processing captured packets.
 *
 * @param short_addr   Device short address.
 * @param panid        PAN ID.
 * @param ext_addr     8-byte IEEE address (may be NULL if unknown).
 * @param frame_counter Observed frame counter value.
 * @return ESP_OK on success, ESP_ERR_NO_MEM if tracking table is full.
 */
esp_err_t zigbee_injector_track_frame_counter(uint16_t short_addr,
                                              uint16_t panid,
                                              const uint8_t *ext_addr,
                                              uint32_t frame_counter);

/**
 * @brief Get the last seen frame counter for a device.
 *
 * @param short_addr   Device short address.
 * @param panid        PAN ID.
 * @param[out] fc_out  Output frame counter value.
 * @return ESP_OK if found, ESP_ERR_NOT_FOUND if not tracked.
 */
esp_err_t zigbee_injector_get_frame_counter(uint16_t short_addr,
                                            uint16_t panid,
                                            uint32_t *fc_out);

/**
 * @brief Replay a captured packet with frame counter manipulation.
 *
 * For modern devices that use frame counter validation:
 * 1. Looks up the target device's last seen frame counter
 * 2. Increments it by `fc_increment`
 * 3. Patches the frame counter in the NWK security header
 * 4. Re-encrypts the modified frame with the provided network key
 * 5. Transmits the modified frame
 *
 * This defeats frame-counter-based replay protection on devices where
 * the network key is known (e.g. extracted via sniffing or install
 * code attack).
 *
 * @param pkt           Captured packet to replay.
 * @param network_key   16-byte network key for re-encryption.
 * @param fc_increment  Amount to add to the tracked counter (typically 1).
 * @return ESP_OK on success.
 */
esp_err_t zigbee_inject_replay_with_counter(const captured_packet_t *pkt,
                                            const uint8_t *network_key,
                                            uint32_t fc_increment);

/**
 * @brief Clear all tracked frame counters.
 *
 * @return ESP_OK.
 */
esp_err_t zigbee_injector_clear_frame_counters(void);

#ifdef __cplusplus
}
#endif

#endif /* ZIGBLADE_ZIGBEE_INJECTOR_H */
