/**
 * @file wifi_bridge.h
 * @brief UART framing contract between ESP32-H2 and ESP32-C5 Wi-Fi companion.
 */

#ifndef ZIGBLADE_WIFI_BRIDGE_H
#define ZIGBLADE_WIFI_BRIDGE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WIFI_BRIDGE_UART_BAUDRATE      1500000U
#define WIFI_BRIDGE_SYNC_WORD          0x5A47U
#define WIFI_BRIDGE_MAX_PAYLOAD        1024U

typedef enum {
    WIFI_BRIDGE_MSG_HELLO          = 0x01,
    WIFI_BRIDGE_MSG_STATUS         = 0x02,
    WIFI_BRIDGE_MSG_CAPTURE_FRAME  = 0x10,
    WIFI_BRIDGE_MSG_CAPTURE_STATS  = 0x11,
    WIFI_BRIDGE_MSG_PCAP_CHUNK     = 0x12,
    WIFI_BRIDGE_MSG_COMMAND        = 0x20,
    WIFI_BRIDGE_MSG_COMMAND_ACK    = 0x21,
    WIFI_BRIDGE_MSG_ERROR          = 0x7F,
} wifi_bridge_msg_type_t;

typedef enum {
    WIFI_BRIDGE_PROTO_UNKNOWN = 0,
    WIFI_BRIDGE_PROTO_ZIGBEE  = 1,
    WIFI_BRIDGE_PROTO_THREAD  = 2,
    WIFI_BRIDGE_PROTO_MATTER  = 3,
} wifi_bridge_protocol_t;

typedef struct __attribute__((packed)) {
    uint16_t sync_word;
    uint8_t  version;
    uint8_t  msg_type;
    uint16_t payload_len;
    uint16_t sequence;
    uint16_t crc16;
} wifi_bridge_header_t;

typedef struct __attribute__((packed)) {
    uint32_t timestamp_us;
    int8_t   rssi;
    uint8_t  channel;
    uint8_t  protocol;
    uint8_t  flags;
    uint16_t frame_len;
} wifi_bridge_capture_meta_t;

/*
 * H2 -> C5 payloads:
 *   HELLO:          uint32_t firmware_caps
 *   STATUS:         struct with uptime, storage free, capture state
 *   CAPTURE_FRAME:  wifi_bridge_capture_meta_t + raw 802.15.4 frame bytes
 *   CAPTURE_STATS:  compact stats blob for current protocol monitor
 *   PCAP_CHUNK:     file_id + offset + binary PCAP data chunk
 *
 * C5 -> H2 payloads:
 *   COMMAND:        opcode + optional args (start capture, stop, set channel, export)
 *   COMMAND_ACK:    opcode + esp_err_t status
 */

#ifdef __cplusplus
}
#endif

#endif /* ZIGBLADE_WIFI_BRIDGE_H */
