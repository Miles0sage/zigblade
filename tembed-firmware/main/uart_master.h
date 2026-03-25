#ifndef ZIGBLADE_TEMBED_UART_MASTER_H
#define ZIGBLADE_TEMBED_UART_MASTER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#ifdef __cplusplus
extern "C" {
#endif

#define UART_MASTER_MAGIC_0             0x5A
#define UART_MASTER_MAGIC_1             0x42
#define UART_MASTER_MAX_PAYLOAD         512U
#define UART_MASTER_BAUD                921600U
#define APP_MAX_SCAN_RESULTS            24U
#define APP_MAX_PACKET_LOG              48U
#define APP_MAX_KEYS                    8U
#define APP_PACKET_PREVIEW_LEN          48U
#define APP_MAX_WIFI_NETWORKS           12U

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
    APP_SCREEN_SPLASH = 0,
    APP_SCREEN_MENU,
    APP_SCREEN_SCAN,
    APP_SCREEN_SNIFFER,
    APP_SCREEN_ATTACKS,
    APP_SCREEN_SUBGHZ,
    APP_SCREEN_WIFI,
    APP_SCREEN_SETTINGS,
    APP_SCREEN_WEB_UI,
} app_screen_t;

typedef enum {
    MENU_SCAN = 0,
    MENU_SNIFFER,
    MENU_ATTACKS,
    MENU_SUBGHZ,
    MENU_WIFI,
    MENU_SETTINGS,
    MENU_WEB_UI,
    MENU_COUNT
} menu_item_t;

typedef struct {
    uint16_t pan_id;
    uint8_t channel;
    uint8_t coordinator_addr[8];
    int8_t rssi;
} zb_network_info_t;

typedef struct {
    uint32_t sequence;
    uint8_t channel;
    int8_t rssi;
    size_t len;
    uint8_t data[APP_PACKET_PREVIEW_LEN];
} zb_packet_info_t;

typedef struct {
    uint32_t sequence;
    uint8_t key[16];
} zb_key_info_t;

typedef struct {
    SemaphoreHandle_t lock;
    app_screen_t screen;
    uint8_t menu_index;
    uint8_t selected_attack;
    uint8_t current_channel;
    int8_t tx_power_dbm;
    uint8_t brightness;
    bool web_ui_active;
    bool wifi_scan_active;
    uart_bridge_state_t h2_state;
    uint32_t total_packets;
    zb_network_info_t networks[APP_MAX_SCAN_RESULTS];
    size_t network_count;
    zb_packet_info_t packets[APP_MAX_PACKET_LOG];
    size_t packet_count;
    size_t packet_head;
    uint32_t next_packet_sequence;
    zb_key_info_t keys[APP_MAX_KEYS];
    size_t key_count;
    char wifi_networks[APP_MAX_WIFI_NETWORKS][33];
    uint8_t wifi_network_count;
    char status_line[96];
} app_state_t;

typedef enum {
    UART_MASTER_EVENT_SCAN_RESULT = 0,
    UART_MASTER_EVENT_SCAN_COMPLETE,
    UART_MASTER_EVENT_PACKET,
    UART_MASTER_EVENT_KEY_FOUND,
    UART_MASTER_EVENT_STATUS,
    UART_MASTER_EVENT_ATTACK_PROGRESS,
    UART_MASTER_EVENT_ATTACK_COMPLETE,
    UART_MASTER_EVENT_ERROR,
} uart_master_event_type_t;

typedef struct {
    uart_master_event_type_t type;
    union {
        zb_network_info_t scan_result;
        struct {
            uint8_t state;
            uint8_t channel;
            uint32_t packet_count;
        } status;
        zb_packet_info_t packet;
        zb_key_info_t key;
        struct {
            uint8_t percent;
            uint32_t packets_sent;
        } attack_progress;
        struct {
            uint8_t result;
        } attack_complete;
        struct {
            uint16_t code;
            char message[96];
        } error;
    } data;
} uart_master_event_t;

typedef void (*uart_master_event_cb_t)(const uart_master_event_t *event, void *ctx);

esp_err_t uart_master_init(int tx_pin,
                           int rx_pin,
                           uint32_t baud,
                           uart_master_event_cb_t event_cb,
                           void *event_ctx);
esp_err_t uart_master_send_command(uart_bridge_cmd_t cmd, const void *payload, uint16_t payload_len);
uint8_t uart_master_crc8(const uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif
