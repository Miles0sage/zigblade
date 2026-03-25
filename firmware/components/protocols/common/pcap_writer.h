/**
 * @file pcap_writer.h
 * @brief PCAP file writer for IEEE 802.15.4 packet captures.
 *
 * Writes standard libpcap format (magic 0xa1b2c3d4) with link-layer
 * type 195 (LINKTYPE_IEEE802_15_4) to SD card or SPIFFS.
 */

#ifndef ZIGBLADE_PCAP_WRITER_H
#define ZIGBLADE_PCAP_WRITER_H

#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Opaque handle for a PCAP file. */
typedef struct pcap_handle *pcap_handle_t;

/**
 * @brief Open a new PCAP file for writing.
 *
 * Creates the file and writes the 24-byte global header.
 * Link-layer type is set to 195 (IEEE 802.15.4).
 *
 * @param filename  Full path (e.g. "/sdcard/capture.pcap").
 * @param[out] handle  Output handle, must be closed with pcap_close().
 * @return ESP_OK on success.
 */
esp_err_t pcap_open(const char *filename, pcap_handle_t *handle);

/**
 * @brief Write a single packet record.
 *
 * @param handle       PCAP handle from pcap_open().
 * @param data         Packet bytes (raw 802.15.4 frame without FCS).
 * @param len          Packet length.
 * @param timestamp_us Capture timestamp in microseconds since boot.
 * @return ESP_OK on success.
 */
esp_err_t pcap_write_packet(pcap_handle_t handle,
                            const uint8_t *data,
                            uint16_t len,
                            uint32_t timestamp_us);

/**
 * @brief Flush and close the PCAP file.
 *
 * @param handle  PCAP handle. Set to NULL after close.
 * @return ESP_OK on success.
 */
esp_err_t pcap_close(pcap_handle_t handle);

/**
 * @brief Get the number of packets written so far.
 *
 * @param handle  PCAP handle.
 * @return Packet count, or 0 if handle is NULL.
 */
uint32_t pcap_get_packet_count(pcap_handle_t handle);

#ifdef __cplusplus
}
#endif

#endif /* ZIGBLADE_PCAP_WRITER_H */
