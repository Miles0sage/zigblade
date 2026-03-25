/**
 * @file zigbee_sniffer.c
 * @brief Zigbee packet sniffer with multi-layer decode, live decryption,
 *        automatic key extraction, and PCAP output.
 */

#include "zigbee_sniffer.h"
#include "ieee802154_hal.h"
#include "frame_parser.h"
#include "pcap_writer.h"
#include "crypto.h"

#include <string.h>
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"

static const char *TAG = "zigbee_sniffer";

/* ── Internal types ───────────────────────────────────────────────── */

typedef struct {
    uint8_t data[ZIGBLADE_MAX_FRAME_LEN];
    uint8_t len;
    int8_t  rssi;
} sniffer_rx_item_t;

/* ── State ────────────────────────────────────────────────────────── */

static bool                     s_active      = false;
static uint8_t                  s_channel     = 0;
static uint32_t                 s_pkt_count   = 0;
static captured_packet_t        s_last_packet;
static SemaphoreHandle_t        s_mutex       = NULL;
static QueueHandle_t            s_rx_queue    = NULL;
static TaskHandle_t             s_task        = NULL;

/* Decryption key table */
static uint8_t  s_keys[SNIFFER_MAX_KEYS][16];
static uint8_t  s_key_count = 0;

/* PCAP output */
static pcap_handle_t            s_pcap_handle = NULL;

/* User callback */
static zigbee_sniffer_callback_t s_user_cb    = NULL;

/* ── Key extraction ───────────────────────────────────────────────── */

/**
 * Attempt to extract a network key from an APS Transport Key command.
 *
 * APS Transport Key (cmd 0x05) payload for standard NWK key:
 *   Key Type (1) | Key (16) | Key Seq Num (1) | Dst Addr (8) | Src Addr (8)
 *
 * This is sent unencrypted during Zigbee 3.0 initial joining when using
 * the well-known Trust Center Link Key (ZigBeeAlliance09).
 */
static void try_extract_transport_key(const parsed_frame_t *frame)
{
    if (!frame->aps_valid) return;
    if (frame->aps.frame_type != ZB_APS_FRAME_TYPE_CMD) return;
    if (frame->aps.aps_cmd_id != ZB_APS_CMD_TRANSPORT_KEY) return;

    /* The APS command payload starts with the command ID byte,
       followed by the Transport Key payload. */
    const uint8_t *p = frame->aps_payload;
    uint8_t plen = frame->aps_payload_len;

    if (p == NULL || plen < 18) return; /* cmd(1) + type(1) + key(16) minimum */

    uint8_t cmd_id  = p[0]; /* Should be 0x05 */
    (void)cmd_id;
    uint8_t key_type = p[1];

    /* Key type 0x01 = Standard NWK Key */
    if (key_type == 0x01 && plen >= 18) {
        const uint8_t *extracted_key = &p[2];

        ESP_LOGW(TAG, "!! Transport Key captured: NWK key extracted !!");
        ESP_LOG_BUFFER_HEX_LEVEL(TAG, extracted_key, 16, ESP_LOG_WARN);

        /* Auto-add to key table */
        if (s_key_count < SNIFFER_MAX_KEYS) {
            /* Check if we already have this key */
            bool duplicate = false;
            for (uint8_t i = 0; i < s_key_count; i++) {
                if (memcmp(s_keys[i], extracted_key, 16) == 0) {
                    duplicate = true;
                    break;
                }
            }
            if (!duplicate) {
                memcpy(s_keys[s_key_count], extracted_key, 16);
                s_key_count++;
                ESP_LOGI(TAG, "Auto-added extracted key (%d/%d)",
                         s_key_count, SNIFFER_MAX_KEYS);
            }
        }
    }
}

/* ── Decryption attempt ───────────────────────────────────────────── */

/**
 * Try to decrypt the NWK payload using stored keys.
 * Returns true if decryption succeeded with any key.
 */
static bool try_decrypt_nwk(parsed_frame_t *frame)
{
    if (!frame->nwk_valid || !frame->nwk.security) return false;
    if (frame->nwk_payload == NULL || frame->nwk_payload_len == 0) return false;
    if (s_key_count == 0) return false;

    uint8_t mic_length = zigbee_mic_len(frame->nwk.sec_level);
    uint8_t encrypted_len = frame->nwk_payload_len;

    if (encrypted_len <= mic_length) return false;

    uint8_t payload_len = encrypted_len - mic_length;
    uint8_t *mic_ptr = &frame->nwk_payload[payload_len];

    /* Build nonce from NWK security header */
    uint8_t nonce[ZIGBEE_NONCE_LEN];
    /* Use source IEEE address from NWK header (extended nonce) */
    uint8_t *src_ieee = frame->nwk.src_ieee;

    /* Build AAD: the NWK header bytes before the encrypted payload */
    const uint8_t *aad = frame->mac_payload;
    uint16_t aad_len = frame->nwk.header_len;

    /* Try each key */
    for (uint8_t k = 0; k < s_key_count; k++) {
        /* Make a copy of the encrypted payload to try decryption */
        uint8_t temp[128];
        if (payload_len > sizeof(temp)) continue;
        memcpy(temp, frame->nwk_payload, payload_len);

        zigbee_derive_nonce(src_ieee, frame->nwk.sec_frame_counter,
                           frame->nwk.sec_level, nonce);

        esp_err_t err = zigblade_aes_ccm_decrypt(
            s_keys[k], nonce, temp, payload_len,
            aad, aad_len, mic_ptr, mic_length);

        if (err == ESP_OK) {
            ESP_LOGI(TAG, "NWK decrypted with key #%d", k);
            /* Copy decrypted payload back */
            memcpy(frame->nwk_payload, temp, payload_len);
            frame->nwk_payload_len = payload_len;

            /* Now try to parse APS from the decrypted payload */
            esp_err_t aps_err = frame_parse_aps(frame->nwk_payload,
                                                 frame->nwk_payload_len,
                                                 &frame->aps);
            if (aps_err == ESP_OK) {
                frame->aps_valid = true;
                frame->aps_payload = frame->nwk_payload + frame->aps.header_len;
                frame->aps_payload_len = frame->nwk_payload_len - frame->aps.header_len;

                /* Try ZCL if it's a data frame */
                if (frame->aps.frame_type == ZB_APS_FRAME_TYPE_DATA &&
                    !frame->aps.security &&
                    frame->aps_payload_len >= 3) {
                    esp_err_t zcl_err = frame_parse_zcl(frame->aps_payload,
                                                         frame->aps_payload_len,
                                                         &frame->zcl);
                    if (zcl_err == ESP_OK) {
                        frame->zcl_valid = true;
                        frame->zcl_payload = frame->aps_payload + frame->zcl.header_len;
                        frame->zcl_payload_len = frame->aps_payload_len - frame->zcl.header_len;
                    }
                }
            }

            return true;
        }
    }

    return false;
}

/* ── RX callback (ISR context) ────────────────────────────────────── */

static void sniffer_rx_callback(uint8_t *frame, uint8_t len, int8_t rssi)
{
    if (s_rx_queue == NULL) return;

    sniffer_rx_item_t item;
    item.len  = (len > sizeof(item.data)) ? sizeof(item.data) : len;
    item.rssi = rssi;
    memcpy(item.data, frame, item.len);

    BaseType_t xHigherPriorityTaskWoken = pdFALSE;
    xQueueSendFromISR(s_rx_queue, &item, &xHigherPriorityTaskWoken);
    if (xHigherPriorityTaskWoken) {
        portYIELD_FROM_ISR();
    }
}

/* ── Sniffer processing task ──────────────────────────────────────── */

static void sniffer_task(void *arg)
{
    (void)arg;
    ESP_LOGI(TAG, "Sniffer task started on channel %d", s_channel);

    while (s_active) {
        sniffer_rx_item_t item;
        if (xQueueReceive(s_rx_queue, &item, pdMS_TO_TICKS(100)) != pdTRUE) {
            continue;
        }

        /* Parse the frame through all layers */
        parsed_frame_t parsed;
        if (frame_parse(item.data, item.len, &parsed) != ESP_OK) {
            continue;
        }

        /* Build captured packet */
        captured_packet_t cap;
        memset(&cap, 0, sizeof(cap));
        memcpy(&cap.parsed, &parsed, sizeof(parsed));
        cap.rssi         = item.rssi;
        cap.channel      = s_channel;
        cap.timestamp_us = (uint32_t)esp_timer_get_time();
        cap.decrypted    = false;

        /* Try to extract transport keys from unencrypted APS commands */
        try_extract_transport_key(&cap.parsed);

        /* Attempt NWK decryption if encrypted */
        if (cap.parsed.nwk_valid && cap.parsed.nwk.security) {
            cap.decrypted = try_decrypt_nwk(&cap.parsed);
        }

        /* Write to PCAP */
        if (s_pcap_handle != NULL) {
            pcap_write_packet(s_pcap_handle, item.data, item.len,
                              cap.timestamp_us);
        }

        /* Update state */
        xSemaphoreTake(s_mutex, portMAX_DELAY);
        memcpy(&s_last_packet, &cap, sizeof(cap));
        s_pkt_count++;
        xSemaphoreGive(s_mutex);

        /* User callback */
        if (s_user_cb != NULL) {
            s_user_cb(&cap);
        }

        /* Log summary */
        ESP_LOGD(TAG, "[%"PRIu32"] %s | src=0x%04X dst=0x%04X | RSSI=%d%s",
                 s_pkt_count,
                 frame_type_str(parsed.mac.frame_type),
                 parsed.mac.src_short_addr,
                 parsed.mac.dst_short_addr,
                 item.rssi,
                 cap.decrypted ? " [DECRYPTED]" : "");
    }

    ESP_LOGI(TAG, "Sniffer task exiting, %"PRIu32" packets captured", s_pkt_count);
    s_task = NULL;
    vTaskDelete(NULL);
}

/* ── Public API ───────────────────────────────────────────────────── */

esp_err_t zigbee_sniffer_start(uint8_t channel)
{
    if (channel < ZIGBLADE_CHANNEL_MIN || channel > ZIGBLADE_CHANNEL_MAX) {
        return ESP_ERR_INVALID_ARG;
    }
    if (s_active) {
        ESP_LOGW(TAG, "Sniffer already active");
        return ESP_ERR_INVALID_STATE;
    }

    /* Init sync primitives */
    if (s_mutex == NULL) {
        s_mutex = xSemaphoreCreateMutex();
        if (s_mutex == NULL) return ESP_ERR_NO_MEM;
    }
    if (s_rx_queue == NULL) {
        s_rx_queue = xQueueCreate(64, sizeof(sniffer_rx_item_t));
        if (s_rx_queue == NULL) return ESP_ERR_NO_MEM;
    }

    s_channel   = channel;
    s_pkt_count = 0;
    s_active    = true;

    /* Configure radio */
    zigblade_radio_set_channel(channel);
    zigblade_radio_register_rx_callback(sniffer_rx_callback);
    zigblade_radio_start_receive();

    /* Launch processing task */
    BaseType_t ret = xTaskCreate(sniffer_task, "zb_sniff", 6144, NULL, 6, &s_task);
    if (ret != pdPASS) {
        s_active = false;
        zigblade_radio_stop_receive();
        return ESP_ERR_NO_MEM;
    }

    ESP_LOGI(TAG, "Sniffer started on channel %d", channel);
    return ESP_OK;
}

esp_err_t zigbee_sniffer_stop(void)
{
    if (!s_active) return ESP_OK;

    s_active = false;

    /* Wait for task to exit */
    while (s_task != NULL) {
        vTaskDelay(pdMS_TO_TICKS(50));
    }

    zigblade_radio_stop_receive();
    zigblade_radio_register_rx_callback(NULL);

    /* Close PCAP if open */
    if (s_pcap_handle != NULL) {
        pcap_close(s_pcap_handle);
        s_pcap_handle = NULL;
    }

    ESP_LOGI(TAG, "Sniffer stopped, %"PRIu32" packets total", s_pkt_count);
    return ESP_OK;
}

esp_err_t zigbee_sniffer_set_key(const uint8_t *key)
{
    if (key == NULL) return ESP_ERR_INVALID_ARG;

    /* Check for duplicates */
    for (uint8_t i = 0; i < s_key_count; i++) {
        if (memcmp(s_keys[i], key, 16) == 0) {
            ESP_LOGD(TAG, "Key already in table");
            return ESP_OK;
        }
    }

    if (s_key_count >= SNIFFER_MAX_KEYS) {
        ESP_LOGW(TAG, "Key table full (%d/%d)", s_key_count, SNIFFER_MAX_KEYS);
        return ESP_ERR_NO_MEM;
    }

    memcpy(s_keys[s_key_count], key, 16);
    s_key_count++;
    ESP_LOGI(TAG, "Key added (%d/%d)", s_key_count, SNIFFER_MAX_KEYS);
    return ESP_OK;
}

esp_err_t zigbee_sniffer_clear_keys(void)
{
    memset(s_keys, 0, sizeof(s_keys));
    s_key_count = 0;
    ESP_LOGI(TAG, "All keys cleared");
    return ESP_OK;
}

uint32_t zigbee_sniffer_get_packet_count(void)
{
    return s_pkt_count;
}

esp_err_t zigbee_sniffer_get_last_packet(captured_packet_t *pkt)
{
    if (pkt == NULL) return ESP_ERR_INVALID_ARG;
    if (s_pkt_count == 0) return ESP_ERR_NOT_FOUND;

    xSemaphoreTake(s_mutex, portMAX_DELAY);
    memcpy(pkt, &s_last_packet, sizeof(*pkt));
    xSemaphoreGive(s_mutex);

    return ESP_OK;
}

esp_err_t zigbee_sniffer_enable_pcap(const char *filepath)
{
    if (filepath == NULL) return ESP_ERR_INVALID_ARG;

    /* Close existing PCAP if any */
    if (s_pcap_handle != NULL) {
        pcap_close(s_pcap_handle);
        s_pcap_handle = NULL;
    }

    return pcap_open(filepath, &s_pcap_handle);
}

esp_err_t zigbee_sniffer_register_callback(zigbee_sniffer_callback_t cb)
{
    s_user_cb = cb;
    return ESP_OK;
}

bool zigbee_sniffer_is_active(void)
{
    return s_active;
}
