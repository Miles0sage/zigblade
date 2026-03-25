/**
 * @file uart_bridge.c
 * @brief ESP32-H2 UART bridge for ZigBlade master/slave control.
 */

#include "uart_bridge.h"

#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "ieee802154_hal.h"
#include "frame_parser.h"
#include "zigbee_injector.h"
#include "zigbee_scanner.h"
#include "zigbee_sniffer.h"

static const char *TAG = "uart_bridge";

typedef struct {
    uint32_t capture_id;
    captured_packet_t packet;
} bridge_capture_entry_t;

typedef struct {
    uart_port_t uart_num;
    bool initialized;
    SemaphoreHandle_t tx_mutex;
    SemaphoreHandle_t capture_mutex;
    uart_bridge_state_t state;
    uint8_t current_channel;
    bool scan_complete_sent;
    uint8_t reported_scan_count;
    uint32_t capture_seq;
    uint32_t last_attack_packets;
    bridge_capture_entry_t captures[UART_BRIDGE_CAPTURE_RING_SIZE];
} uart_bridge_context_t;

static uart_bridge_context_t s_bridge = {
    .uart_num = UART_BRIDGE_DEFAULT_UART,
    .state = UART_BRIDGE_STATE_IDLE,
    .current_channel = ZIGBLADE_CHANNEL_MIN,
};

static uint8_t s_rx_accumulator[UART_BRIDGE_RX_BUFFER_SIZE];
static size_t s_rx_accumulator_len = 0;

static uint16_t rd_le16(const uint8_t *buf)
{
    return (uint16_t)buf[0] | ((uint16_t)buf[1] << 8);
}

static void wr_le16(uint8_t *buf, uint16_t value)
{
    buf[0] = (uint8_t)(value & 0xFF);
    buf[1] = (uint8_t)((value >> 8) & 0xFF);
}

static void wr_le32(uint8_t *buf, uint32_t value)
{
    buf[0] = (uint8_t)(value & 0xFF);
    buf[1] = (uint8_t)((value >> 8) & 0xFF);
    buf[2] = (uint8_t)((value >> 16) & 0xFF);
    buf[3] = (uint8_t)((value >> 24) & 0xFF);
}

static void bridge_log_if_error(const char *action, esp_err_t err)
{
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "%s: %s", action, esp_err_to_name(err));
    }
}

uint8_t uart_bridge_crc8(const uint8_t *data, size_t len)
{
    uint8_t crc = 0x00;

    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (uint8_t bit = 0; bit < 8; bit++) {
            crc = (crc & 0x80U) ? (uint8_t)((crc << 1) ^ 0x07U) : (uint8_t)(crc << 1);
        }
    }

    return crc;
}

static esp_err_t bridge_send_frame(uint8_t response_id, const uint8_t *payload, uint16_t payload_len)
{
    if (!s_bridge.initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    if (payload_len > UART_BRIDGE_MAX_PAYLOAD) {
        return ESP_ERR_INVALID_SIZE;
    }

    uint8_t frame[sizeof(uart_bridge_frame_header_t) + UART_BRIDGE_MAX_PAYLOAD + 1];
    uart_bridge_frame_header_t *header = (uart_bridge_frame_header_t *)frame;

    header->magic[0] = UART_BRIDGE_MAGIC_0;
    header->magic[1] = UART_BRIDGE_MAGIC_1;
    header->command_id = response_id;
    wr_le16((uint8_t *)&header->payload_len_le, payload_len);

    if (payload_len > 0 && payload != NULL) {
        memcpy(frame + sizeof(*header), payload, payload_len);
    }

    const size_t crc_pos = sizeof(*header) + payload_len;
    frame[crc_pos] = uart_bridge_crc8(frame, crc_pos);

    xSemaphoreTake(s_bridge.tx_mutex, portMAX_DELAY);
    int written = uart_write_bytes(s_bridge.uart_num, (const char *)frame, crc_pos + 1);
    uart_wait_tx_done(s_bridge.uart_num, pdMS_TO_TICKS(50));
    xSemaphoreGive(s_bridge.tx_mutex);

    return (written == (int)(crc_pos + 1)) ? ESP_OK : ESP_FAIL;
}

static esp_err_t bridge_send_error(uint16_t code, const char *fmt, ...)
{
    char message[96];
    va_list args;
    va_start(args, fmt);
    vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);

    const size_t msg_len = strnlen(message, sizeof(message));
    uint8_t payload[2 + sizeof(message)];

    wr_le16(payload, code);
    memcpy(payload + 2, message, msg_len);

    return bridge_send_frame(RSP_ERROR, payload, (uint16_t)(2 + msg_len));
}

static esp_err_t bridge_send_status(void)
{
    uint8_t payload[sizeof(uart_bridge_status_payload_t)];
    uart_bridge_status_payload_t status = {
        .state = (uint8_t)s_bridge.state,
        .channel = s_bridge.current_channel,
        .packet_count = zigbee_sniffer_get_packet_count(),
    };

    memcpy(payload, &status, sizeof(status));
    return bridge_send_frame(RSP_STATUS, payload, sizeof(payload));
}

static void bridge_store_capture(const captured_packet_t *pkt)
{
    if (pkt == NULL) {
        return;
    }

    xSemaphoreTake(s_bridge.capture_mutex, portMAX_DELAY);
    const uint32_t capture_id = s_bridge.capture_seq++;
    const size_t slot = capture_id % UART_BRIDGE_CAPTURE_RING_SIZE;
    s_bridge.captures[slot].capture_id = capture_id;
    memcpy(&s_bridge.captures[slot].packet, pkt, sizeof(*pkt));
    xSemaphoreGive(s_bridge.capture_mutex);
}

static esp_err_t bridge_lookup_capture(uint32_t capture_id, captured_packet_t *pkt)
{
    if (pkt == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t err = ESP_ERR_NOT_FOUND;

    xSemaphoreTake(s_bridge.capture_mutex, portMAX_DELAY);
    for (size_t i = 0; i < UART_BRIDGE_CAPTURE_RING_SIZE; i++) {
        if (s_bridge.captures[i].capture_id == capture_id) {
            memcpy(pkt, &s_bridge.captures[i].packet, sizeof(*pkt));
            err = ESP_OK;
            break;
        }
    }
    xSemaphoreGive(s_bridge.capture_mutex);

    return err;
}

static void bridge_send_transport_key_if_present(const captured_packet_t *pkt)
{
    const parsed_frame_t *frame = &pkt->parsed;
    if (!frame->aps_valid) {
        return;
    }
    if (frame->aps.frame_type != ZB_APS_FRAME_TYPE_CMD ||
        frame->aps.aps_cmd_id != ZB_APS_CMD_TRANSPORT_KEY ||
        frame->aps_payload == NULL ||
        frame->aps_payload_len < 18 ||
        frame->aps_payload[1] != 0x01) {
        return;
    }

    bridge_send_frame(RSP_KEY_FOUND, &frame->aps_payload[2], 16);
}

static void bridge_sniffer_callback(const captured_packet_t *pkt)
{
    if (pkt == NULL) {
        return;
    }

    bridge_store_capture(pkt);

    if ((size_t)(2 + pkt->parsed.raw_len) > UART_BRIDGE_MAX_PAYLOAD) {
        ESP_LOGW(TAG, "Dropping oversized packet len=%u", pkt->parsed.raw_len);
        return;
    }

    uint8_t payload[UART_BRIDGE_MAX_PAYLOAD];
    payload[0] = pkt->channel;
    payload[1] = (uint8_t)pkt->rssi;
    memcpy(payload + 2, pkt->parsed.raw, pkt->parsed.raw_len);

    bridge_send_frame(RSP_PACKET, payload, (uint16_t)(2 + pkt->parsed.raw_len));
    bridge_send_transport_key_if_present(pkt);
}

static esp_err_t bridge_stop_scan_if_needed(void)
{
    const zigbee_scan_result_t *results = zigbee_scan_get_results();
    if (results->scan_active) {
        zigbee_scan_stop();
        for (uint8_t i = 0; i < 20 && zigbee_scan_get_results()->scan_active; i++) {
            vTaskDelay(pdMS_TO_TICKS(25));
        }
        s_bridge.scan_complete_sent = true;
        s_bridge.reported_scan_count = zigbee_scan_get_results()->count;
    }
    return ESP_OK;
}

static esp_err_t bridge_stop_sniffer_if_needed(void)
{
    if (zigbee_sniffer_is_active()) {
        bridge_log_if_error("zigbee_sniffer_stop", zigbee_sniffer_stop());
    }
    return ESP_OK;
}

static const zigbee_network_t *bridge_select_network(uint8_t channel)
{
    const zigbee_scan_result_t *results = zigbee_scan_get_results();

    for (uint8_t i = 0; i < results->count; i++) {
        if (results->networks[i].channel == channel) {
            return &results->networks[i];
        }
    }

    return (results->count > 0) ? &results->networks[0] : NULL;
}

static esp_err_t bridge_handle_scan_start(const uint8_t *payload, uint16_t payload_len)
{
    if (payload_len != 1) {
        return bridge_send_error(UART_BRIDGE_ERR_BAD_PAYLOAD, "scan_start expects 1 byte");
    }

    const uint8_t channel = payload[0];
    bridge_stop_sniffer_if_needed();
    bridge_log_if_error("zigbee_scan_clear", zigbee_scan_clear());

    esp_err_t err = (channel == 0xFF) ? zigbee_scan_start() : zigbee_scan_channel(channel);
    if (err != ESP_OK) {
        return bridge_send_error(UART_BRIDGE_ERR_RADIO_BUSY, "scan start failed: %s", esp_err_to_name(err));
    }

    s_bridge.state = UART_BRIDGE_STATE_SCANNING;
    s_bridge.current_channel = (channel == 0xFF) ? ZIGBLADE_CHANNEL_MIN : channel;
    s_bridge.reported_scan_count = 0;
    s_bridge.scan_complete_sent = false;
    return ESP_OK;
}

static esp_err_t bridge_handle_scan_stop(void)
{
    esp_err_t err = zigbee_scan_stop();
    if (err == ESP_OK) {
        s_bridge.state = UART_BRIDGE_STATE_IDLE;
    }
    return (err == ESP_OK) ? ESP_OK :
        bridge_send_error(UART_BRIDGE_ERR_INTERNAL, "scan stop failed: %s", esp_err_to_name(err));
}

static esp_err_t bridge_handle_sniff_start(const uint8_t *payload, uint16_t payload_len)
{
    if (!(payload_len == 1 || payload_len == 17)) {
        return bridge_send_error(UART_BRIDGE_ERR_BAD_PAYLOAD, "sniff_start expects ch or ch+key");
    }

    const uint8_t channel = payload[0];
    if (channel < ZIGBLADE_CHANNEL_MIN || channel > ZIGBLADE_CHANNEL_MAX) {
        return bridge_send_error(UART_BRIDGE_ERR_BAD_PAYLOAD, "invalid sniff channel %u", channel);
    }

    bridge_stop_scan_if_needed();
    bridge_stop_sniffer_if_needed();
    bridge_log_if_error("zigbee_sniffer_register_callback",
                        zigbee_sniffer_register_callback(bridge_sniffer_callback));

    xSemaphoreTake(s_bridge.capture_mutex, portMAX_DELAY);
    s_bridge.capture_seq = 0;
    for (size_t i = 0; i < UART_BRIDGE_CAPTURE_RING_SIZE; i++) {
        s_bridge.captures[i].capture_id = UINT32_MAX;
    }
    xSemaphoreGive(s_bridge.capture_mutex);

    if (payload_len == 17) {
        esp_err_t key_err = zigbee_sniffer_set_key(payload + 1);
        if (key_err != ESP_OK) {
            return bridge_send_error(UART_BRIDGE_ERR_INTERNAL, "set sniff key failed: %s", esp_err_to_name(key_err));
        }
    }

    esp_err_t err = zigbee_sniffer_start(channel);
    if (err != ESP_OK) {
        return bridge_send_error(UART_BRIDGE_ERR_RADIO_BUSY, "sniffer start failed: %s", esp_err_to_name(err));
    }

    s_bridge.state = UART_BRIDGE_STATE_SNIFFING;
    s_bridge.current_channel = channel;
    return ESP_OK;
}

static esp_err_t bridge_handle_sniff_stop(void)
{
    esp_err_t err = zigbee_sniffer_stop();
    if (err == ESP_OK) {
        s_bridge.state = UART_BRIDGE_STATE_IDLE;
    }
    return (err == ESP_OK) ? ESP_OK :
        bridge_send_error(UART_BRIDGE_ERR_INTERNAL, "sniffer stop failed: %s", esp_err_to_name(err));
}

static esp_err_t bridge_handle_inject(const uint8_t *payload, uint16_t payload_len)
{
    if (payload_len == 0 || payload_len > 125) {
        return bridge_send_error(UART_BRIDGE_ERR_BAD_PAYLOAD, "inject len must be 1..125");
    }

    esp_err_t err = zigbee_inject_raw((uint8_t *)payload, (uint8_t)payload_len);
    return (err == ESP_OK) ? ESP_OK :
        bridge_send_error(UART_BRIDGE_ERR_INTERNAL, "inject failed: %s", esp_err_to_name(err));
}

static esp_err_t bridge_handle_replay(const uint8_t *payload, uint16_t payload_len)
{
    if (payload_len != 4) {
        return bridge_send_error(UART_BRIDGE_ERR_BAD_PAYLOAD, "replay expects 4-byte capture id");
    }

    captured_packet_t pkt;
    const uint32_t capture_id = (uint32_t)payload[0] |
                                ((uint32_t)payload[1] << 8) |
                                ((uint32_t)payload[2] << 16) |
                                ((uint32_t)payload[3] << 24);

    esp_err_t err = bridge_lookup_capture(capture_id, &pkt);
    if (err != ESP_OK) {
        return bridge_send_error(UART_BRIDGE_ERR_NOT_FOUND, "capture %" PRIu32 " not in ring", capture_id);
    }

    err = zigbee_inject_replay(&pkt);
    return (err == ESP_OK) ? ESP_OK :
        bridge_send_error(UART_BRIDGE_ERR_INTERNAL, "replay failed: %s", esp_err_to_name(err));
}

static esp_err_t bridge_handle_set_channel(const uint8_t *payload, uint16_t payload_len)
{
    if (payload_len != 1) {
        return bridge_send_error(UART_BRIDGE_ERR_BAD_PAYLOAD, "set_channel expects 1 byte");
    }

    const uint8_t channel = payload[0];
    if (channel < ZIGBLADE_CHANNEL_MIN || channel > ZIGBLADE_CHANNEL_MAX) {
        return bridge_send_error(UART_BRIDGE_ERR_BAD_PAYLOAD, "invalid channel %u", channel);
    }

    esp_err_t err;
    bridge_stop_scan_if_needed();
    if (zigbee_sniffer_is_active()) {
        bridge_log_if_error("zigbee_sniffer_stop", zigbee_sniffer_stop());
        bridge_log_if_error("zigbee_sniffer_register_callback",
                            zigbee_sniffer_register_callback(bridge_sniffer_callback));
        err = zigbee_sniffer_start(channel);
    } else {
        err = zigblade_radio_set_channel(channel);
    }

    if (err != ESP_OK) {
        return bridge_send_error(UART_BRIDGE_ERR_INTERNAL, "set channel failed: %s", esp_err_to_name(err));
    }

    s_bridge.current_channel = channel;
    return ESP_OK;
}

static esp_err_t bridge_handle_set_key(const uint8_t *payload, uint16_t payload_len)
{
    if (payload_len != 16) {
        return bridge_send_error(UART_BRIDGE_ERR_BAD_PAYLOAD, "set_key expects 16 bytes");
    }

    esp_err_t err = zigbee_sniffer_set_key(payload);
    return (err == ESP_OK) ? ESP_OK :
        bridge_send_error(UART_BRIDGE_ERR_INTERNAL, "set_key failed: %s", esp_err_to_name(err));
}

static esp_err_t bridge_handle_disassoc(const uint8_t *payload, uint16_t payload_len)
{
    if (payload_len != 2) {
        return bridge_send_error(UART_BRIDGE_ERR_BAD_PAYLOAD, "disassoc expects 2-byte target");
    }

    const zigbee_network_t *network = bridge_select_network(s_bridge.current_channel);
    if (network == NULL) {
        return bridge_send_error(UART_BRIDGE_ERR_NOT_FOUND, "no scanned network for disassoc context");
    }

    const uint16_t target = rd_le16(payload);
    s_bridge.state = UART_BRIDGE_STATE_ATTACKING;
    bridge_send_frame(RSP_ATTACK_PROGRESS, (const uint8_t[]){0, 0, 0, 0, 0}, 5);

    esp_err_t err = zigbee_inject_disassoc(target, network->pan_id, network->coord_short_addr);
    if (err != ESP_OK) {
        s_bridge.state = UART_BRIDGE_STATE_IDLE;
        return bridge_send_error(UART_BRIDGE_ERR_INTERNAL, "disassoc failed: %s", esp_err_to_name(err));
    }

    const uint32_t sent = zigbee_injector_get_tx_count();
    uint8_t progress_payload[5];
    progress_payload[0] = 100;
    wr_le32(progress_payload + 1, sent);
    bridge_send_frame(RSP_ATTACK_PROGRESS, progress_payload, sizeof(progress_payload));
    s_bridge.state = UART_BRIDGE_STATE_IDLE;
    return bridge_send_frame(RSP_ATTACK_COMPLETE, (const uint8_t[]){0x00}, 1);
}

static esp_err_t bridge_handle_beacon_flood(const uint8_t *payload, uint16_t payload_len)
{
    if (payload_len != 2) {
        return bridge_send_error(UART_BRIDGE_ERR_BAD_PAYLOAD, "beacon_flood expects 2-byte PAN ID");
    }

    const uint16_t panid = rd_le16(payload);
    const uint8_t channel = s_bridge.current_channel;
    s_bridge.state = UART_BRIDGE_STATE_ATTACKING;
    s_bridge.last_attack_packets = zigbee_injector_get_tx_count();

    for (uint32_t i = 0; i < UART_BRIDGE_BEACON_FLOOD_FRAMES; i++) {
        esp_err_t err = zigbee_inject_beacon(panid, channel);
        if (err != ESP_OK) {
            s_bridge.state = UART_BRIDGE_STATE_IDLE;
            return bridge_send_error(UART_BRIDGE_ERR_INTERNAL, "beacon_flood failed at %lu: %s",
                                     (unsigned long)i, esp_err_to_name(err));
        }

        if ((i % 8U) == 0U || i == (UART_BRIDGE_BEACON_FLOOD_FRAMES - 1U)) {
            uint8_t progress_payload[5];
            progress_payload[0] = (uint8_t)(((i + 1U) * 100U) / UART_BRIDGE_BEACON_FLOOD_FRAMES);
            wr_le32(progress_payload + 1, zigbee_injector_get_tx_count() - s_bridge.last_attack_packets);
            bridge_send_frame(RSP_ATTACK_PROGRESS, progress_payload, sizeof(progress_payload));
        }

        vTaskDelay(pdMS_TO_TICKS(5));
    }

    s_bridge.state = UART_BRIDGE_STATE_IDLE;
    return bridge_send_frame(RSP_ATTACK_COMPLETE, (const uint8_t[]){0x00}, 1);
}

static esp_err_t bridge_dispatch_command(uint8_t command_id, const uint8_t *payload, uint16_t payload_len)
{
    switch (command_id) {
    case CMD_SCAN_START:
        return bridge_handle_scan_start(payload, payload_len);
    case CMD_SCAN_STOP:
        return bridge_handle_scan_stop();
    case CMD_SNIFF_START:
        return bridge_handle_sniff_start(payload, payload_len);
    case CMD_SNIFF_STOP:
        return bridge_handle_sniff_stop();
    case CMD_INJECT:
        return bridge_handle_inject(payload, payload_len);
    case CMD_REPLAY:
        return bridge_handle_replay(payload, payload_len);
    case CMD_SET_CHANNEL:
        return bridge_handle_set_channel(payload, payload_len);
    case CMD_SET_KEY:
        return bridge_handle_set_key(payload, payload_len);
    case CMD_GET_STATUS:
        return bridge_send_status();
    case CMD_ATTACK_DISASSOC:
        return bridge_handle_disassoc(payload, payload_len);
    case CMD_ATTACK_BEACON_FLOOD:
        return bridge_handle_beacon_flood(payload, payload_len);
    case CMD_ATTACK_TOUCHLINK:
    case CMD_ATTACK_FUZZ:
        return bridge_send_error(UART_BRIDGE_ERR_UNSUPPORTED, "command 0x%02X not implemented by current APIs",
                                 command_id);
    default:
        return bridge_send_error(UART_BRIDGE_ERR_BAD_COMMAND, "unknown command 0x%02X", command_id);
    }
}

static void bridge_monitor_scan(void)
{
    const zigbee_scan_result_t *results = zigbee_scan_get_results();

    if (results->scan_active) {
        s_bridge.state = UART_BRIDGE_STATE_SCANNING;
        s_bridge.current_channel = results->current_channel;
    }

    while (s_bridge.reported_scan_count < results->count) {
        const zigbee_network_t *network = &results->networks[s_bridge.reported_scan_count];
        uart_bridge_scan_result_payload_t payload = {
            .pan_id = network->pan_id,
            .channel = network->channel,
            .rssi = network->rssi,
        };

        memset(payload.coordinator_addr, 0, sizeof(payload.coordinator_addr));
        if (network->ext_addr_valid) {
            memcpy(payload.coordinator_addr, network->coord_ext_addr, sizeof(payload.coordinator_addr));
        } else {
            wr_le16(payload.coordinator_addr, network->coord_short_addr);
        }

        bridge_send_frame(RSP_SCAN_RESULT, (const uint8_t *)&payload, sizeof(payload));
        s_bridge.reported_scan_count++;
    }

    if (!results->scan_active && !s_bridge.scan_complete_sent && s_bridge.state == UART_BRIDGE_STATE_SCANNING) {
        s_bridge.state = UART_BRIDGE_STATE_IDLE;
        s_bridge.scan_complete_sent = true;
        bridge_send_frame(RSP_SCAN_COMPLETE, NULL, 0);
    }
}

static void bridge_consume_rx_bytes(const uint8_t *data, size_t len)
{
    if (len == 0) {
        return;
    }

    if ((s_rx_accumulator_len + len) > sizeof(s_rx_accumulator)) {
        s_rx_accumulator_len = 0;
    }

    memcpy(s_rx_accumulator + s_rx_accumulator_len, data, len);
    s_rx_accumulator_len += len;

    while (s_rx_accumulator_len >= (sizeof(uart_bridge_frame_header_t) + 1U)) {
        size_t offset = 0;
        while (offset + 1 < s_rx_accumulator_len &&
               (s_rx_accumulator[offset] != UART_BRIDGE_MAGIC_0 ||
                s_rx_accumulator[offset + 1] != UART_BRIDGE_MAGIC_1)) {
            offset++;
        }

        if (offset > 0) {
            memmove(s_rx_accumulator, s_rx_accumulator + offset, s_rx_accumulator_len - offset);
            s_rx_accumulator_len -= offset;
            if (s_rx_accumulator_len < (sizeof(uart_bridge_frame_header_t) + 1U)) {
                return;
            }
        }

        const uart_bridge_frame_header_t *header = (const uart_bridge_frame_header_t *)s_rx_accumulator;
        const uint16_t payload_len = rd_le16((const uint8_t *)&header->payload_len_le);
        const size_t total_len = sizeof(*header) + payload_len + 1U;

        if (payload_len > UART_BRIDGE_MAX_PAYLOAD) {
            bridge_send_error(UART_BRIDGE_ERR_BAD_LENGTH, "payload %u exceeds max", payload_len);
            memmove(s_rx_accumulator, s_rx_accumulator + 1, s_rx_accumulator_len - 1);
            s_rx_accumulator_len--;
            continue;
        }

        if (s_rx_accumulator_len < total_len) {
            return;
        }

        const uint8_t crc = s_rx_accumulator[total_len - 1U];
        const uint8_t computed_crc = uart_bridge_crc8(s_rx_accumulator, total_len - 1U);
        if (crc != computed_crc) {
            bridge_send_error(UART_BRIDGE_ERR_BAD_CRC, "crc mismatch");
            memmove(s_rx_accumulator, s_rx_accumulator + 1, s_rx_accumulator_len - 1);
            s_rx_accumulator_len--;
            continue;
        }

        bridge_dispatch_command(header->command_id, s_rx_accumulator + sizeof(*header), payload_len);
        memmove(s_rx_accumulator, s_rx_accumulator + total_len, s_rx_accumulator_len - total_len);
        s_rx_accumulator_len -= total_len;
    }
}

esp_err_t uart_bridge_init(uart_port_t uart_num, int tx_pin, int rx_pin, uint32_t baud)
{
    const uart_config_t cfg = {
        .baud_rate = (int)baud,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
#if SOC_UART_SUPPORT_XTAL_CLK
        .source_clk = UART_SCLK_XTAL,
#endif
    };

    esp_err_t err = uart_driver_install(uart_num, UART_BRIDGE_RX_BUFFER_SIZE, 0, 0, NULL, 0);
    if (err != ESP_OK) {
        return err;
    }

    err = uart_param_config(uart_num, &cfg);
    if (err != ESP_OK) {
        return err;
    }

    err = uart_set_pin(uart_num, tx_pin, rx_pin, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
    if (err != ESP_OK) {
        return err;
    }

    if (s_bridge.tx_mutex == NULL) {
        s_bridge.tx_mutex = xSemaphoreCreateMutex();
    }
    if (s_bridge.capture_mutex == NULL) {
        s_bridge.capture_mutex = xSemaphoreCreateMutex();
    }
    if (s_bridge.tx_mutex == NULL || s_bridge.capture_mutex == NULL) {
        return ESP_ERR_NO_MEM;
    }

    memset(s_bridge.captures, 0, sizeof(s_bridge.captures));
    for (size_t i = 0; i < UART_BRIDGE_CAPTURE_RING_SIZE; i++) {
        s_bridge.captures[i].capture_id = UINT32_MAX;
    }
    s_bridge.uart_num = uart_num;
    s_bridge.current_channel = zigblade_radio_get_channel();
    s_bridge.initialized = true;
    s_bridge.reported_scan_count = 0;
    s_bridge.scan_complete_sent = true;

    ESP_LOGI(TAG, "UART bridge ready on UART%d TX=%d RX=%d baud=%" PRIu32,
             uart_num, tx_pin, rx_pin, baud);

    return ESP_OK;
}

void uart_bridge_task(void *arg)
{
    (void)arg;

    uint8_t rx_buf[256];
    bridge_send_status();

    for (;;) {
        int read = uart_read_bytes(s_bridge.uart_num, rx_buf, sizeof(rx_buf), pdMS_TO_TICKS(20));
        if (read > 0) {
            bridge_consume_rx_bytes(rx_buf, (size_t)read);
        }

        bridge_monitor_scan();
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}
