/**
 * @file thread_sniffer.c
 * @brief Passive Thread sniffer with MeshCoP credential extraction and PCAP output.
 */

#include "thread_sniffer.h"

#include <inttypes.h>
#include <string.h>
#include "esp_log.h"
#include "frame_parser.h"
#include "pcap_writer.h"

static const char *TAG = "thread_sniffer";

typedef struct {
    bool     valid;
    bool     long_addr;
    uint16_t short_addr;
    uint8_t  ext_addr[8];
} thread_seen_device_t;

static thread_sniffer_stats_t s_stats;
static thread_credentials_t   s_credentials;
static thread_seen_device_t   s_devices[THREAD_SNIFFER_MAX_DEVICES];
static uint32_t               s_device_count = 0;
static uint32_t               s_pps_window_packets = 0;
static int64_t                s_last_pps_window_us = 0;
static pcap_handle_t          s_pcap = NULL;

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

static bool payload_has_be16(const uint8_t *payload, uint8_t len, uint16_t value)
{
    for (uint8_t i = 0; i + 1 < len; i++) {
        if (payload[i] == (uint8_t)(value >> 8) && payload[i + 1] == (uint8_t)value) {
            return true;
        }
    }
    return false;
}

static void update_devices(const mac_header_t *mac)
{
    thread_seen_device_t candidate = {0};
    if (mac->src_addr_mode == IEEE802154_ADDR_MODE_SHORT) {
        candidate.valid = true;
        candidate.long_addr = false;
        candidate.short_addr = mac->src_short_addr;
    } else if (mac->src_addr_mode == IEEE802154_ADDR_MODE_LONG) {
        candidate.valid = true;
        candidate.long_addr = true;
        memcpy(candidate.ext_addr, mac->src_ext_addr, sizeof(candidate.ext_addr));
    }

    if (!candidate.valid) {
        return;
    }

    for (uint32_t i = 0; i < s_device_count; i++) {
        if (!s_devices[i].valid || s_devices[i].long_addr != candidate.long_addr) {
            continue;
        }
        if ((!candidate.long_addr && s_devices[i].short_addr == candidate.short_addr) ||
            (candidate.long_addr &&
             memcmp(s_devices[i].ext_addr, candidate.ext_addr, sizeof(candidate.ext_addr)) == 0)) {
            return;
        }
    }

    if (s_device_count < THREAD_SNIFFER_MAX_DEVICES) {
        s_devices[s_device_count++] = candidate;
        s_stats.unique_devices = s_device_count;
    }
}

static void extract_credentials(const uint8_t *payload, uint8_t len)
{
    for (uint8_t i = 0; i + 2 <= len; ) {
        uint8_t type = payload[i++];
        uint8_t tlv_len = payload[i++];
        if ((uint16_t)i + tlv_len > len) {
            break;
        }

        const uint8_t *value = &payload[i];
        switch (type) {
        case 0x02:
            if (tlv_len == 8) {
                memcpy(s_credentials.ext_pan_id, value, 8);
                s_credentials.has_ext_pan_id = true;
            }
            break;
        case 0x03:
            if (tlv_len > 0) {
                uint8_t copy_len = (tlv_len >= sizeof(s_credentials.network_name)) ?
                                   sizeof(s_credentials.network_name) - 1 : tlv_len;
                memcpy(s_credentials.network_name, value, copy_len);
                s_credentials.network_name[copy_len] = '\0';
                s_credentials.has_network_name = true;
            }
            break;
        case 0x04:
            if (tlv_len == 16) {
                memcpy(s_credentials.pskc, value, 16);
                s_credentials.has_pskc = true;
                s_credentials.commissioning_seen = true;
            }
            break;
        case 0x05:
            if (tlv_len == 16) {
                memcpy(s_credentials.network_key, value, 16);
                s_credentials.has_network_key = true;
                s_credentials.commissioning_seen = true;
            }
            break;
        default:
            break;
        }

        i += tlv_len;
    }
}

esp_err_t thread_sniffer_start(void)
{
    memset(&s_stats, 0, sizeof(s_stats));
    memset(&s_credentials, 0, sizeof(s_credentials));
    memset(s_devices, 0, sizeof(s_devices));
    s_device_count = 0;
    s_stats.active = true;
    s_last_pps_window_us = 0;
    s_pps_window_packets = 0;
    ESP_LOGI(TAG, "Thread sniffer enabled");
    return ESP_OK;
}

esp_err_t thread_sniffer_stop(void)
{
    s_stats.active = false;
    if (s_pcap != NULL) {
        pcap_close(s_pcap);
        s_pcap = NULL;
    }
    ESP_LOGI(TAG, "Thread sniffer stopped (%" PRIu32 " packets)", s_stats.total_packets);
    return ESP_OK;
}

esp_err_t thread_sniffer_enable_pcap(const char *filepath)
{
    if (filepath == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    if (s_pcap != NULL) {
        pcap_close(s_pcap);
        s_pcap = NULL;
    }

    return pcap_open(filepath, &s_pcap);
}

esp_err_t thread_sniffer_get_stats(thread_sniffer_stats_t *stats)
{
    if (stats == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    memcpy(stats, &s_stats, sizeof(*stats));
    return ESP_OK;
}

esp_err_t thread_sniffer_get_credentials(thread_credentials_t *credentials)
{
    if (credentials == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    memcpy(credentials, &s_credentials, sizeof(*credentials));
    return ESP_OK;
}

void thread_sniffer_process_packet(const uint8_t *frame,
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

    int64_t now_us = timestamp_us;
    if (s_last_pps_window_us == 0) {
        s_last_pps_window_us = now_us;
    } else if ((now_us - s_last_pps_window_us) >= 1000000LL) {
        s_stats.packets_per_sec = s_pps_window_packets;
        s_pps_window_packets = 0;
        s_last_pps_window_us = now_us;
    }

    s_stats.total_packets++;
    s_pps_window_packets++;
    s_stats.current_channel = channel;
    update_devices(&mac);

    if (payload_has_be16(payload, payload_len, 0x4D4C)) {
        s_stats.mle_packets++;
    }
    if (payload_has_be16(payload, payload_len, 0x15A4)) {
        s_stats.matter_candidates++;
    }

    uint32_t before_commission = s_credentials.commissioning_seen;
    extract_credentials(payload, payload_len);
    if (!before_commission && s_credentials.commissioning_seen) {
        ESP_LOGW(TAG, "Thread commissioning material observed on channel %u", channel);
    }
    if (s_credentials.commissioning_seen) {
        s_stats.commissioning_packets++;
    }

    if (s_pcap != NULL) {
        pcap_write_packet(s_pcap, frame, len, timestamp_us);
    }
}
