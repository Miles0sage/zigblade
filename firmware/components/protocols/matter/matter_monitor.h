/**
 * @file matter_monitor.h
 * @brief Passive Matter-over-Thread session monitor and lab DeeDoS probe builder.
 */

#ifndef ZIGBLADE_MATTER_MONITOR_H
#define ZIGBLADE_MATTER_MONITOR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MATTER_MONITOR_MAX_SESSIONS 16
#define MATTER_DEEDOS_PROBE_LEN     32

typedef struct {
    bool     active;
    uint16_t session_id;
    uint32_t message_counter;
    uint16_t source_short_addr;
    uint16_t dest_short_addr;
    uint8_t  channel;
    uint32_t message_count;
    uint32_t last_seen_ms;
    bool     suspicious_deedos_pattern;
} matter_session_t;

typedef struct {
    bool     active;
    uint32_t total_packets;
    uint32_t matter_over_thread_packets;
    uint32_t active_sessions;
    uint32_t deedos_candidates;
    uint8_t  last_channel;
} matter_monitor_stats_t;

esp_err_t matter_monitor_start(void);
esp_err_t matter_monitor_stop(void);
esp_err_t matter_monitor_get_stats(matter_monitor_stats_t *stats);
size_t matter_monitor_get_sessions(matter_session_t *sessions, size_t max_sessions);
void matter_monitor_process_packet(const uint8_t *frame,
                                   uint8_t len,
                                   int8_t rssi,
                                   uint8_t channel,
                                   uint32_t timestamp_us);
esp_err_t matter_monitor_build_deedos_probe(uint8_t *buffer,
                                            size_t buffer_len,
                                            size_t *probe_len);

#ifdef __cplusplus
}
#endif

#endif /* ZIGBLADE_MATTER_MONITOR_H */
