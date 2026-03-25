/**
 * @file thread_scanner.c
 * @brief Passive Thread discovery and MeshCoP dataset extraction.
 */

#include "thread_scanner.h"
#include "crypto.h"

#include <inttypes.h>
#include <string.h>
#include "esp_log.h"
#include "esp_timer.h"
#include "frame_parser.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/cmac.h"

static const char *TAG = "thread_scanner";

static thread_scan_result_t s_results;

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

static bool payload_contains(const uint8_t *payload, uint8_t len, uint16_t value_be)
{
    if (payload == NULL || len < 2) {
        return false;
    }

    uint8_t msb = (uint8_t)(value_be >> 8);
    uint8_t lsb = (uint8_t)(value_be & 0xFF);
    for (uint8_t i = 0; i + 1 < len; i++) {
        if (payload[i] == msb && payload[i + 1] == lsb) {
            return true;
        }
    }

    return false;
}

static void extract_meshcop_tlvs(thread_network_t *net, const uint8_t *payload, uint8_t len)
{
    if (net == NULL || payload == NULL) {
        return;
    }

    for (uint8_t i = 0; i + 2 <= len; ) {
        uint8_t type = payload[i++];
        uint8_t tlv_len = payload[i++];
        if ((uint16_t)i + tlv_len > len) {
            break;
        }

        const uint8_t *value = &payload[i];
        switch (type) {
        case 0x00: /* Channel */
            if (tlv_len >= 3) {
                net->channel = value[2];
            }
            break;
        case 0x01: /* PAN ID */
            if (tlv_len >= 2) {
                net->pan_id = ((uint16_t)value[0] << 8) | value[1];
            }
            break;
        case 0x02: /* Extended PAN ID */
            if (tlv_len == 8) {
                memcpy(net->ext_pan_id, value, 8);
                net->ext_pan_id_valid = true;
            }
            break;
        case 0x03: /* Network Name */
            if (tlv_len > 0) {
                uint8_t copy_len = (tlv_len >= sizeof(net->network_name)) ?
                                   sizeof(net->network_name) - 1 : tlv_len;
                memcpy(net->network_name, value, copy_len);
                net->network_name[copy_len] = '\0';
                net->network_name_valid = true;
            }
            break;
        case 0x05: /* Network Master Key */
        case 0x04: /* PSKc */
            net->commissioning_seen = true;
            break;
        default:
            break;
        }

        i += tlv_len;
    }
}

static thread_network_t *get_or_create_network(const mac_header_t *mac, uint8_t channel)
{
    for (uint8_t i = 0; i < s_results.count; i++) {
        if (s_results.networks[i].pan_id == mac->dst_panid &&
            s_results.networks[i].channel == channel) {
            return &s_results.networks[i];
        }
    }

    if (s_results.count >= THREAD_SCAN_MAX_NETWORKS) {
        return NULL;
    }

    thread_network_t *net = &s_results.networks[s_results.count++];
    memset(net, 0, sizeof(*net));
    net->pan_id = mac->dst_panid;
    net->channel = channel;
    net->rssi = -127;
    return net;
}

esp_err_t thread_scan_start(void)
{
    memset(&s_results, 0, sizeof(s_results));
    s_results.scan_active = true;
    s_results.current_channel = 11;
    ESP_LOGI(TAG, "Thread discovery started");
    return ESP_OK;
}

esp_err_t thread_scan_stop(void)
{
    s_results.scan_active = false;
    ESP_LOGI(TAG, "Thread discovery stopped (%u network(s))", s_results.count);
    return ESP_OK;
}

esp_err_t thread_scan_clear(void)
{
    memset(&s_results, 0, sizeof(s_results));
    return ESP_OK;
}

const thread_scan_result_t *thread_scan_get_results(void)
{
    return &s_results;
}

void thread_scan_process_packet(const uint8_t *frame,
                                uint8_t len,
                                int8_t rssi,
                                uint8_t channel,
                                uint32_t timestamp_us)
{
    (void)timestamp_us;

    if (!s_results.scan_active || frame == NULL || len == 0) {
        return;
    }

    s_results.current_channel = channel;

    mac_header_t mac;
    if (frame_parse_mac(frame, len, &mac) != ESP_OK) {
        return;
    }

    if (mac.frame_type != IEEE802154_FRAME_TYPE_DATA || mac.header_len >= len) {
        return;
    }

    const uint8_t *payload = &frame[mac.header_len];
    uint8_t payload_len = len - mac.header_len;
    if (!lowpan_like(payload, payload_len)) {
        return;
    }

    thread_network_t *net = get_or_create_network(&mac, channel);
    if (net == NULL) {
        return;
    }

    net->leader_short_addr = mac.src_short_addr;
    net->last_seen_ms = timestamp_us / 1000;
    if (rssi > net->rssi) {
        net->rssi = rssi;
    }
    if (mac.src_addr_mode == IEEE802154_ADDR_MODE_LONG) {
        memcpy(net->leader_ext_addr, mac.src_ext_addr, sizeof(net->leader_ext_addr));
        net->leader_ext_addr_valid = true;
    }

    if (payload_contains(payload, payload_len, 0x4D4C)) {
        net->mle_advertisement_seen = true;
        s_results.mle_advertisements++;
    }

    extract_meshcop_tlvs(net, payload, payload_len);
}
