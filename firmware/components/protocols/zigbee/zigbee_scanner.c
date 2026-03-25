/**
 * @file zigbee_scanner.c
 * @brief Zigbee network scanner — discovers networks by parsing beacons.
 */

#include "zigbee_scanner.h"
#include "ieee802154_hal.h"
#include "frame_parser.h"

#include <string.h>
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"

static const char *TAG = "zigbee_scanner";

/* ── Internal types ───────────────────────────────────────────────── */

/** Raw frame delivered from ISR via queue */
typedef struct {
    uint8_t data[ZIGBLADE_MAX_FRAME_LEN];
    uint8_t len;
    int8_t  rssi;
} scan_rx_item_t;

/* ── State ────────────────────────────────────────────────────────── */

static zigbee_scan_result_t s_results;
static SemaphoreHandle_t    s_results_mutex = NULL;
static QueueHandle_t        s_rx_queue      = NULL;
static TaskHandle_t         s_scan_task     = NULL;
static bool                 s_stop_request  = false;

/* Channels to scan (set by start functions) */
static uint8_t  s_channels[ZIGBLADE_NUM_CHANNELS];
static uint8_t  s_num_channels = 0;

/* ── Beacon payload parsing ───────────────────────────────────────── */

/**
 * Parse the MAC beacon payload (superframe spec + GTS + pending addr +
 * beacon payload) to extract Zigbee network info.
 *
 * IEEE 802.15.4 beacon payload format:
 *   Superframe Spec (2) | GTS Spec (1) | Pending Addr Spec (1) | Beacon Payload
 *
 * Zigbee beacon payload (after MAC-level fields):
 *   Protocol ID (1) | Stack Profile/Version (1) | Router Cap (1) |
 *   Device Depth/ED Cap (1) | Extended PAN ID (8) | TX Offset (3)
 *   [Optional: Update ID (1)]
 */
static void parse_beacon(const uint8_t *payload, uint8_t payload_len,
                          const mac_header_t *mac, int8_t rssi,
                          uint8_t channel)
{
    if (payload_len < 4) {
        return; /* Too short for superframe + GTS + pending */
    }

    /* Superframe specification (2 bytes) */
    uint16_t superframe = (uint16_t)payload[0] | ((uint16_t)payload[1] << 8);
    bool assoc_permit = (superframe >> 15) & 0x01;

    /* GTS specification (1 byte) */
    uint8_t gts_spec = payload[2];
    uint8_t gts_count = gts_spec & 0x07;
    uint8_t gts_bytes = (gts_count > 0) ? (1 + gts_count * 3) : 0;

    /* Pending address specification (1 byte) */
    uint8_t pos = 3;
    if (pos >= payload_len) return;
    uint8_t pending_spec = payload[pos++];
    uint8_t n_short_pend = pending_spec & 0x07;
    uint8_t n_long_pend  = (pending_spec >> 4) & 0x07;
    pos += gts_bytes;
    pos += n_short_pend * 2 + n_long_pend * 8;

    if (pos >= payload_len) return;

    /* Zigbee beacon payload starts here */
    uint8_t *zb = (uint8_t *)&payload[pos];
    uint8_t  zb_len = payload_len - pos;

    if (zb_len < 15) {
        ESP_LOGD(TAG, "Zigbee beacon payload too short: %d", zb_len);
        return;
    }

    uint8_t protocol_id = zb[0];
    if (protocol_id != 0x00) {
        ESP_LOGD(TAG, "Not a Zigbee beacon (protocol_id=0x%02X)", protocol_id);
        return;
    }

    uint8_t stack_nwk    = zb[1];
    uint8_t stack_profile = stack_nwk & 0x0F;
    uint8_t nwk_version   = (stack_nwk >> 4) & 0x0F;

    uint8_t cap_byte = zb[2];
    uint8_t router_cap = cap_byte & 0x01;  /* bit 0: router capacity */
    uint8_t depth_byte = zb[3];
    uint8_t end_dev_cap = depth_byte & 0x01; /* bit 0: end device capacity */
    /* bits 1-4: device depth */
    /* bit 7: security */
    bool security = (cap_byte >> 2) & 0x01;  /* Zigbee 3.0: security bit */

    /* Extended PAN ID at zb[4..11] — informational, not used for filtering */

    /* ── Store or update network entry ────────────────────────── */

    xSemaphoreTake(s_results_mutex, portMAX_DELAY);

    zigbee_network_t *net = NULL;

    /* Search for existing entry */
    for (uint8_t i = 0; i < s_results.count; i++) {
        if (s_results.networks[i].pan_id == mac->dst_panid &&
            s_results.networks[i].channel == channel) {
            net = &s_results.networks[i];
            break;
        }
    }

    /* Create new entry if not found */
    if (net == NULL && s_results.count < ZIGBEE_SCAN_MAX_NETWORKS) {
        net = &s_results.networks[s_results.count];
        memset(net, 0, sizeof(*net));
        s_results.count++;
    }

    if (net != NULL) {
        net->pan_id             = mac->dst_panid;
        net->channel            = channel;
        net->coord_short_addr   = mac->src_short_addr;
        net->stack_profile      = stack_profile;
        net->zigbee_version     = nwk_version;
        net->security_enabled   = security;
        net->permit_joining     = assoc_permit;
        net->router_capacity    = router_cap;
        net->end_device_capacity = end_dev_cap;
        net->last_seen_ms       = (uint32_t)(esp_timer_get_time() / 1000);

        if (rssi > net->rssi || net->rssi == 0) {
            net->rssi = rssi;
        }

        if (mac->src_addr_mode == IEEE802154_ADDR_MODE_LONG) {
            memcpy(net->coord_ext_addr, mac->src_ext_addr, 8);
            net->ext_addr_valid = true;
        }
    }

    xSemaphoreGive(s_results_mutex);
}

/**
 * Track unique device addresses seen on each network (from data frames).
 */
static void track_device(uint16_t panid, uint8_t channel,
                          uint16_t src_addr, int8_t rssi)
{
    xSemaphoreTake(s_results_mutex, portMAX_DELAY);

    for (uint8_t i = 0; i < s_results.count; i++) {
        zigbee_network_t *net = &s_results.networks[i];
        if (net->pan_id == panid && net->channel == channel) {
            /* Simple device count — increment if below cap.
               A real implementation would track unique addresses. */
            if (net->device_count < ZIGBEE_SCAN_MAX_DEVICES) {
                net->device_count++;
            }
            if (rssi > net->rssi) {
                net->rssi = rssi;
            }
            net->last_seen_ms = (uint32_t)(esp_timer_get_time() / 1000);
            break;
        }
    }

    xSemaphoreGive(s_results_mutex);
}

/* ── RX callback (ISR context) ────────────────────────────────────── */

static void scanner_rx_callback(uint8_t *frame, uint8_t len, int8_t rssi)
{
    if (s_rx_queue == NULL) {
        return;
    }

    scan_rx_item_t item;
    item.len  = (len > sizeof(item.data)) ? sizeof(item.data) : len;
    item.rssi = rssi;
    memcpy(item.data, frame, item.len);

    /* Non-blocking enqueue from ISR */
    BaseType_t xHigherPriorityTaskWoken = pdFALSE;
    xQueueSendFromISR(s_rx_queue, &item, &xHigherPriorityTaskWoken);
    if (xHigherPriorityTaskWoken) {
        portYIELD_FROM_ISR();
    }
}

/* ── Scanner task ─────────────────────────────────────────────────── */

static void scan_task(void *arg)
{
    (void)arg;

    ESP_LOGI(TAG, "Scan task started, %d channel(s)", s_num_channels);

    for (uint8_t ch_idx = 0; ch_idx < s_num_channels && !s_stop_request; ch_idx++) {
        uint8_t channel = s_channels[ch_idx];

        xSemaphoreTake(s_results_mutex, portMAX_DELAY);
        s_results.current_channel = channel;
        xSemaphoreGive(s_results_mutex);

        ESP_LOGI(TAG, "Scanning channel %d", channel);
        zigblade_radio_set_channel(channel);
        zigblade_radio_start_receive();

        /* Dwell on this channel */
        TickType_t start = xTaskGetTickCount();
        TickType_t dwell = pdMS_TO_TICKS(ZIGBEE_SCAN_DWELL_MS);

        while ((xTaskGetTickCount() - start) < dwell && !s_stop_request) {
            scan_rx_item_t item;
            if (xQueueReceive(s_rx_queue, &item, pdMS_TO_TICKS(50)) == pdTRUE) {
                /* Parse MAC header */
                mac_header_t mac;
                if (frame_parse_mac(item.data, item.len, &mac) != ESP_OK) {
                    continue;
                }

                if (mac.frame_type == IEEE802154_FRAME_TYPE_BEACON) {
                    /* Parse beacon payload */
                    uint8_t *payload = &item.data[mac.header_len];
                    uint8_t  plen    = item.len - mac.header_len;
                    parse_beacon(payload, plen, &mac, item.rssi, channel);
                } else if (mac.frame_type == IEEE802154_FRAME_TYPE_DATA) {
                    /* Track devices from data frames */
                    if (mac.src_addr_mode == IEEE802154_ADDR_MODE_SHORT) {
                        track_device(mac.dst_panid, channel,
                                     mac.src_short_addr, item.rssi);
                    }
                }
            }
        }

        zigblade_radio_stop_receive();
    }

    /* Mark scan as complete */
    xSemaphoreTake(s_results_mutex, portMAX_DELAY);
    s_results.scan_active = false;
    xSemaphoreGive(s_results_mutex);

    ESP_LOGI(TAG, "Scan complete, found %d network(s)", s_results.count);

    /* Unregister callback */
    zigblade_radio_register_rx_callback(NULL);

    s_scan_task = NULL;
    vTaskDelete(NULL);
}

/* ── Public API ───────────────────────────────────────────────────── */

esp_err_t zigbee_scan_start(void)
{
    if (s_scan_task != NULL) {
        ESP_LOGW(TAG, "Scan already in progress");
        return ESP_ERR_INVALID_STATE;
    }

    /* Initialize synchronization primitives */
    if (s_results_mutex == NULL) {
        s_results_mutex = xSemaphoreCreateMutex();
        if (s_results_mutex == NULL) return ESP_ERR_NO_MEM;
    }
    if (s_rx_queue == NULL) {
        s_rx_queue = xQueueCreate(32, sizeof(scan_rx_item_t));
        if (s_rx_queue == NULL) return ESP_ERR_NO_MEM;
    }

    /* Set up all 16 channels */
    s_num_channels = 0;
    for (uint8_t ch = ZIGBLADE_CHANNEL_MIN; ch <= ZIGBLADE_CHANNEL_MAX; ch++) {
        s_channels[s_num_channels++] = ch;
    }

    s_stop_request = false;
    s_results.scan_active = true;

    /* Register our RX callback */
    zigblade_radio_register_rx_callback(scanner_rx_callback);

    /* Launch scan task */
    BaseType_t ret = xTaskCreate(scan_task, "zb_scan", 4096, NULL, 5, &s_scan_task);
    if (ret != pdPASS) {
        ESP_LOGE(TAG, "Failed to create scan task");
        s_results.scan_active = false;
        return ESP_ERR_NO_MEM;
    }

    ESP_LOGI(TAG, "Full scan started (channels 11-26)");
    return ESP_OK;
}

esp_err_t zigbee_scan_channel(uint8_t channel)
{
    if (channel < ZIGBLADE_CHANNEL_MIN || channel > ZIGBLADE_CHANNEL_MAX) {
        return ESP_ERR_INVALID_ARG;
    }
    if (s_scan_task != NULL) {
        ESP_LOGW(TAG, "Scan already in progress");
        return ESP_ERR_INVALID_STATE;
    }

    if (s_results_mutex == NULL) {
        s_results_mutex = xSemaphoreCreateMutex();
        if (s_results_mutex == NULL) return ESP_ERR_NO_MEM;
    }
    if (s_rx_queue == NULL) {
        s_rx_queue = xQueueCreate(32, sizeof(scan_rx_item_t));
        if (s_rx_queue == NULL) return ESP_ERR_NO_MEM;
    }

    s_channels[0]  = channel;
    s_num_channels = 1;
    s_stop_request = false;
    s_results.scan_active = true;

    zigblade_radio_register_rx_callback(scanner_rx_callback);

    BaseType_t ret = xTaskCreate(scan_task, "zb_scan", 4096, NULL, 5, &s_scan_task);
    if (ret != pdPASS) {
        s_results.scan_active = false;
        return ESP_ERR_NO_MEM;
    }

    ESP_LOGI(TAG, "Single-channel scan started (ch %d)", channel);
    return ESP_OK;
}

esp_err_t zigbee_scan_stop(void)
{
    s_stop_request = true;
    ESP_LOGI(TAG, "Scan stop requested");
    return ESP_OK;
}

const zigbee_scan_result_t *zigbee_scan_get_results(void)
{
    return &s_results;
}

esp_err_t zigbee_scan_clear(void)
{
    if (s_results_mutex != NULL) {
        xSemaphoreTake(s_results_mutex, portMAX_DELAY);
    }

    memset(&s_results, 0, sizeof(s_results));

    if (s_results_mutex != NULL) {
        xSemaphoreGive(s_results_mutex);
    }

    ESP_LOGI(TAG, "Scan results cleared");
    return ESP_OK;
}
