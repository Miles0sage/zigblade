/**
 * @file zigbee_sniffer.h
 * @brief Zigbee packet sniffer with decoding and PCAP output.
 */

#ifndef ZIGBLADE_ZIGBEE_SNIFFER_H
#define ZIGBLADE_ZIGBEE_SNIFFER_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"
#include "frame_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum keys the sniffer can hold for decryption attempts. */
#define SNIFFER_MAX_KEYS    8
#define ZIGBEE_SNIFFER_AUTO_CHANNEL 0
#define ZIGBEE_SNIFFER_DEFAULT_HOP_MS 250

typedef struct {
    uint32_t total_packets;
    uint32_t packets_per_sec;
    uint32_t unique_devices;
    uint32_t zigbee_packets;
    uint32_t thread_packets;
    uint32_t matter_packets;
    uint32_t unknown_packets;
    uint8_t  current_channel;
    bool     channel_hopping;
} zigbee_sniffer_stats_t;

/** Captured packet with decoded metadata */
typedef struct {
    parsed_frame_t parsed;          /**< Full multi-layer parse         */
    int8_t         rssi;            /**< Signal strength                */
    uint8_t        channel;         /**< Channel it was captured on     */
    uint32_t       timestamp_us;    /**< Capture time (us since boot)   */
    bool           decrypted;       /**< Was NWK/APS payload decrypted  */
} captured_packet_t;

/**
 * @brief Callback invoked for each captured and decoded packet.
 *
 * @param pkt  Pointer to the captured packet (valid only during callback).
 */
typedef void (*zigbee_sniffer_callback_t)(const captured_packet_t *pkt);

/**
 * @brief Start sniffing on the specified channel.
 *
 * Puts the radio into promiscuous receive on `channel` and begins
 * capturing, decoding, and (optionally) writing packets to PCAP.
 *
 * @param channel  802.15.4 channel (11-26).
 * @return ESP_OK on success.
 */
esp_err_t zigbee_sniffer_start(uint8_t channel);

/**
 * @brief Start sniffing with round-robin channel hopping across channels 11-26.
 *
 * @return ESP_OK on success.
 */
esp_err_t zigbee_sniffer_start_auto_hop(void);

/**
 * @brief Stop sniffing and release resources.
 *
 * If a PCAP file is open, it is flushed and closed.
 *
 * @return ESP_OK.
 */
esp_err_t zigbee_sniffer_stop(void);

/**
 * @brief Add a decryption key for live decryption of sniffed traffic.
 *
 * Up to SNIFFER_MAX_KEYS keys can be stored. The sniffer tries each
 * key when it encounters encrypted NWK or APS frames.
 *
 * @param key  16-byte AES-128 key.
 * @return ESP_OK, or ESP_ERR_NO_MEM if key table is full.
 */
esp_err_t zigbee_sniffer_set_key(const uint8_t *key);

/**
 * @brief Clear all stored decryption keys.
 *
 * @return ESP_OK.
 */
esp_err_t zigbee_sniffer_clear_keys(void);

/**
 * @brief Get total number of packets captured since sniffer start.
 *
 * @return Packet count.
 */
uint32_t zigbee_sniffer_get_packet_count(void);

/**
 * @brief Get the last captured packet.
 *
 * Returns a copy of the most recent captured packet. The caller
 * provides the output buffer.
 *
 * @param[out] pkt  Output buffer for the last packet.
 * @return ESP_OK if a packet is available, ESP_ERR_NOT_FOUND if none yet.
 */
esp_err_t zigbee_sniffer_get_last_packet(captured_packet_t *pkt);

/**
 * @brief Enable PCAP file writing.
 *
 * @param filepath  Path to PCAP file (e.g. "/sdcard/zigbee.pcap").
 * @return ESP_OK on success.
 */
esp_err_t zigbee_sniffer_enable_pcap(const char *filepath);

/**
 * @brief Register a per-packet callback.
 *
 * @param cb  Callback function, or NULL to unregister.
 * @return ESP_OK.
 */
esp_err_t zigbee_sniffer_register_callback(zigbee_sniffer_callback_t cb);

/**
 * @brief Retrieve the current capture statistics snapshot.
 *
 * @param[out] stats Output structure.
 * @return ESP_OK on success.
 */
esp_err_t zigbee_sniffer_get_stats(zigbee_sniffer_stats_t *stats);

/**
 * @brief Check if the sniffer is currently active.
 *
 * @return true if sniffing.
 */
bool zigbee_sniffer_is_active(void);

#ifdef __cplusplus
}
#endif

#endif /* ZIGBLADE_ZIGBEE_SNIFFER_H */
