/**
 * @file thread_sniffer.h
 * @brief Passive Thread sniffer fed from shared 802.15.4 captures.
 */

#ifndef ZIGBLADE_THREAD_SNIFFER_H
#define ZIGBLADE_THREAD_SNIFFER_H

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define THREAD_SNIFFER_MAX_DEVICES 128

typedef struct {
    uint32_t total_packets;
    uint32_t packets_per_sec;
    uint32_t unique_devices;
    uint32_t mle_packets;
    uint32_t commissioning_packets;
    uint32_t matter_candidates;
    uint8_t  current_channel;
    bool     active;
} thread_sniffer_stats_t;

typedef struct {
    bool     commissioning_seen;
    bool     has_network_name;
    bool     has_ext_pan_id;
    bool     has_network_key;
    bool     has_pskc;
    char     network_name[17];
    uint8_t  ext_pan_id[8];
    uint8_t  network_key[16];
    uint8_t  pskc[16];
} thread_credentials_t;

esp_err_t thread_sniffer_start(void);
esp_err_t thread_sniffer_stop(void);
esp_err_t thread_sniffer_enable_pcap(const char *filepath);
esp_err_t thread_sniffer_get_stats(thread_sniffer_stats_t *stats);
esp_err_t thread_sniffer_get_credentials(thread_credentials_t *credentials);
void thread_sniffer_process_packet(const uint8_t *frame,
                                   uint8_t len,
                                   int8_t rssi,
                                   uint8_t channel,
                                   uint32_t timestamp_us);

#ifdef __cplusplus
}
#endif

#endif /* ZIGBLADE_THREAD_SNIFFER_H */
