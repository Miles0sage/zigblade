/**
 * @file thread_scanner.h
 * @brief Passive Thread network discovery from shared 802.15.4 captures.
 */

#ifndef ZIGBLADE_THREAD_SCANNER_H
#define ZIGBLADE_THREAD_SCANNER_H

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define THREAD_SCAN_MAX_NETWORKS 32

typedef struct {
    uint16_t pan_id;
    uint8_t  channel;
    uint16_t leader_short_addr;
    uint8_t  leader_ext_addr[8];
    bool     leader_ext_addr_valid;
    uint8_t  ext_pan_id[8];
    bool     ext_pan_id_valid;
    char     network_name[17];
    bool     network_name_valid;
    bool     mle_advertisement_seen;
    bool     commissioning_seen;
    int8_t   rssi;
    uint32_t last_seen_ms;
} thread_network_t;

typedef struct {
    thread_network_t networks[THREAD_SCAN_MAX_NETWORKS];
    uint8_t          count;
    bool             scan_active;
    uint8_t          current_channel;
    uint32_t         mle_advertisements;
} thread_scan_result_t;

esp_err_t thread_scan_start(void);
esp_err_t thread_scan_stop(void);
esp_err_t thread_scan_clear(void);
const thread_scan_result_t *thread_scan_get_results(void);
void thread_scan_process_packet(const uint8_t *frame,
                                uint8_t len,
                                int8_t rssi,
                                uint8_t channel,
                                uint32_t timestamp_us);

#ifdef __cplusplus
}
#endif

#endif /* ZIGBLADE_THREAD_SCANNER_H */
