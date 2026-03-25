/**
 * @file uart_bridge.h
 * @brief UART bridge protocol and ESP32-H2 slave task for ZigBlade.
 */

#ifndef ZIGBLADE_UART_BRIDGE_H
#define ZIGBLADE_UART_BRIDGE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "driver/uart.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define UART_BRIDGE_MAGIC_0               0x5A
#define UART_BRIDGE_MAGIC_1               0x42
#define UART_BRIDGE_DEFAULT_UART          UART_NUM_1
#define UART_BRIDGE_DEFAULT_BAUD          921600U
#define UART_BRIDGE_DEFAULT_TX_PIN        0
#define UART_BRIDGE_DEFAULT_RX_PIN        1
#define UART_BRIDGE_MAX_PAYLOAD           512U
#define UART_BRIDGE_RX_BUFFER_SIZE        2048U
#define UART_BRIDGE_CAPTURE_RING_SIZE     32U
#define UART_BRIDGE_BEACON_FLOOD_FRAMES   64U

typedef enum {
    CMD_SCAN_START            = 0x01,
    CMD_SCAN_STOP             = 0x02,
    CMD_SNIFF_START           = 0x03,
    CMD_SNIFF_STOP            = 0x04,
    CMD_INJECT                = 0x05,
    CMD_REPLAY                = 0x06,
    CMD_SET_CHANNEL           = 0x07,
    CMD_SET_KEY               = 0x08,
    CMD_GET_STATUS            = 0x09,
    CMD_ATTACK_TOUCHLINK      = 0x0A,
    CMD_ATTACK_DISASSOC       = 0x0B,
    CMD_ATTACK_BEACON_FLOOD   = 0x0C,
    CMD_ATTACK_FUZZ           = 0x0D,
} uart_bridge_cmd_t;

typedef enum {
    RSP_SCAN_RESULT       = 0x81,
    RSP_SCAN_COMPLETE     = 0x82,
    RSP_PACKET            = 0x83,
    RSP_KEY_FOUND         = 0x84,
    RSP_STATUS            = 0x85,
    RSP_ATTACK_PROGRESS   = 0x86,
    RSP_ATTACK_COMPLETE   = 0x87,
    RSP_ERROR             = 0x88,
} uart_bridge_rsp_t;

typedef enum {
    UART_BRIDGE_STATE_IDLE      = 0x00,
    UART_BRIDGE_STATE_SCANNING  = 0x01,
    UART_BRIDGE_STATE_SNIFFING  = 0x02,
    UART_BRIDGE_STATE_ATTACKING = 0x03,
} uart_bridge_state_t;

typedef enum {
    UART_BRIDGE_ERR_NONE                = 0x0000,
    UART_BRIDGE_ERR_BAD_MAGIC           = 0x0001,
    UART_BRIDGE_ERR_BAD_LENGTH          = 0x0002,
    UART_BRIDGE_ERR_BAD_CRC             = 0x0003,
    UART_BRIDGE_ERR_BAD_COMMAND         = 0x0004,
    UART_BRIDGE_ERR_BAD_PAYLOAD         = 0x0005,
    UART_BRIDGE_ERR_RADIO_BUSY          = 0x0006,
    UART_BRIDGE_ERR_NOT_FOUND           = 0x0007,
    UART_BRIDGE_ERR_UNSUPPORTED         = 0x0008,
    UART_BRIDGE_ERR_INTERNAL            = 0x0009,
} uart_bridge_error_t;

typedef struct __attribute__((packed)) {
    uint8_t magic[2];
    uint8_t command_id;
    uint16_t payload_len_le;
} uart_bridge_frame_header_t;

typedef struct __attribute__((packed)) {
    uint16_t pan_id;
    uint8_t channel;
    uint8_t coordinator_addr[8];
    int8_t rssi;
} uart_bridge_scan_result_payload_t;

typedef struct __attribute__((packed)) {
    uint8_t state;
    uint8_t channel;
    uint32_t packet_count;
} uart_bridge_status_payload_t;

/*
 * Frame format:
 *   magic[0]=0x5A, magic[1]=0x42, command_or_response_id, payload_len_le, payload, crc8
 *
 * Selected payload layouts:
 *   CMD_SCAN_START:          [channel] where 0xFF means channels 11-26
 *   CMD_SNIFF_START:         [channel] or [channel][16-byte key]
 *   CMD_REPLAY:              [4-byte capture id, little endian, zero-based order since last sniff start]
 *   RSP_SCAN_RESULT:         uart_bridge_scan_result_payload_t
 *   RSP_PACKET:              [channel][rssi][raw IEEE 802.15.4 frame]
 *   RSP_KEY_FOUND:           [16-byte network key]
 *   RSP_STATUS:              uart_bridge_status_payload_t
 *   RSP_ATTACK_PROGRESS:     [percent][4-byte packets_sent_le]
 *   RSP_ATTACK_COMPLETE:     [result]
 *   RSP_ERROR:               [2-byte error code_le][ASCII message bytes]
 */

esp_err_t uart_bridge_init(uart_port_t uart_num, int tx_pin, int rx_pin, uint32_t baud);
void uart_bridge_task(void *arg);
uint8_t uart_bridge_crc8(const uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* ZIGBLADE_UART_BRIDGE_H */
