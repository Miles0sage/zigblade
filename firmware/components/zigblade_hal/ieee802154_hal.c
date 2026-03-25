/**
 * @file ieee802154_hal.c
 * @brief IEEE 802.15.4 HAL implementation for ESP32-H2 using esp_ieee802154 API.
 */

#include "ieee802154_hal.h"

#include <string.h>
#include "esp_log.h"
#include "esp_ieee802154.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static const char *TAG = "zigblade_hal";

/* ── State ─────────────────────────────────────────────────────────── */

static bool              s_initialized  = false;
static bool              s_receiving    = false;
static uint8_t           s_channel      = ZIGBLADE_CHANNEL_MIN;
static zigblade_rx_callback_t s_rx_cb   = NULL;
static SemaphoreHandle_t s_tx_done_sem  = NULL;

/* ── ESP-IDF 802.15.4 callbacks (called from ISR context) ────────── */

/**
 * Called by the driver when a frame is received.
 * We forward it to the user-registered callback.
 */
void esp_ieee802154_receive_done(uint8_t *frame, esp_ieee802154_frame_info_t *frame_info)
{
    if (frame == NULL || frame_info == NULL) {
        return;
    }

    /*
     * frame[0] = PHY length (number of octets in MPDU, including FCS).
     * The actual MAC payload starts at frame[1].
     * frame_info->rssi contains the RSSI of the received frame.
     *
     * We pass &frame[1] (the MPDU without the length byte) and
     * frame[0] - 2 (strip the 2-byte FCS that HW already checked).
     */
    uint8_t mpdu_len = frame[0];
    if (mpdu_len < 2) {
        return; /* impossibly short */
    }
    uint8_t payload_len = mpdu_len - 2; /* exclude FCS */

    if (s_rx_cb != NULL) {
        s_rx_cb(&frame[1], payload_len, frame_info->rssi);
    }

    /* Return the buffer back to the driver for reuse. */
    esp_ieee802154_receive_handle_done(frame);
}

/**
 * Called when a transmission completes successfully.
 */
void esp_ieee802154_transmit_done(const uint8_t *frame,
                                  const uint8_t *ack,
                                  esp_ieee802154_frame_info_t *ack_frame_info)
{
    (void)frame;
    (void)ack;
    (void)ack_frame_info;

    if (s_tx_done_sem != NULL) {
        BaseType_t xHigherPriorityTaskWoken = pdFALSE;
        xSemaphoreGiveFromISR(s_tx_done_sem, &xHigherPriorityTaskWoken);
        if (xHigherPriorityTaskWoken) {
            portYIELD_FROM_ISR();
        }
    }
}

/**
 * Called when transmission fails.
 */
void esp_ieee802154_transmit_failed(const uint8_t *frame, esp_ieee802154_tx_error_t error)
{
    (void)frame;
    ESP_EARLY_LOGW(TAG, "TX failed, error=%d", (int)error);

    if (s_tx_done_sem != NULL) {
        BaseType_t xHigherPriorityTaskWoken = pdFALSE;
        xSemaphoreGiveFromISR(s_tx_done_sem, &xHigherPriorityTaskWoken);
        if (xHigherPriorityTaskWoken) {
            portYIELD_FROM_ISR();
        }
    }
}

/**
 * Called when energy detection completes (unused but required).
 */
void esp_ieee802154_energy_detect_done(int8_t power)
{
    (void)power;
}

/**
 * Called on CCA-done (unused but required by some IDF versions).
 */
void esp_ieee802154_receive_sfd_done(void)
{
    /* no-op */
}

/* ── Public API ────────────────────────────────────────────────────── */

esp_err_t zigblade_radio_init(void)
{
    if (s_initialized) {
        ESP_LOGW(TAG, "Radio already initialized");
        return ESP_OK;
    }

    ESP_LOGI(TAG, "Initializing IEEE 802.15.4 radio");

    /* Create TX-done semaphore (binary) */
    s_tx_done_sem = xSemaphoreCreateBinary();
    if (s_tx_done_sem == NULL) {
        ESP_LOGE(TAG, "Failed to create TX semaphore");
        return ESP_ERR_NO_MEM;
    }

    /* Enable the 802.15.4 subsystem */
    esp_err_t err = esp_ieee802154_enable();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ieee802154_enable failed: %s", esp_err_to_name(err));
        vSemaphoreDelete(s_tx_done_sem);
        s_tx_done_sem = NULL;
        return err;
    }

    /* Set promiscuous mode so we receive all frames */
    esp_ieee802154_set_promiscuous(true);

    /* Disable auto-ACK — we are a passive sniffer / active injector */
    esp_ieee802154_set_rx_when_idle(true);

    /* Default channel */
    esp_ieee802154_set_channel(ZIGBLADE_CHANNEL_MIN);
    s_channel = ZIGBLADE_CHANNEL_MIN;

    /* Default PAN ID: broadcast (accept everything) */
    esp_ieee802154_set_panid(ZIGBLADE_PROMISC_PANID);

    /* Set coordinator = false; we're a sniffer, not a real device */
    esp_ieee802154_set_coordinator(false);

    s_initialized = true;
    ESP_LOGI(TAG, "Radio initialized, channel=%d", s_channel);
    return ESP_OK;
}

esp_err_t zigblade_radio_deinit(void)
{
    if (!s_initialized) {
        return ESP_OK;
    }

    zigblade_radio_stop_receive();

    esp_err_t err = esp_ieee802154_disable();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ieee802154_disable failed: %s", esp_err_to_name(err));
        return err;
    }

    if (s_tx_done_sem != NULL) {
        vSemaphoreDelete(s_tx_done_sem);
        s_tx_done_sem = NULL;
    }

    s_rx_cb = NULL;
    s_initialized = false;
    ESP_LOGI(TAG, "Radio deinitialized");
    return ESP_OK;
}

esp_err_t zigblade_radio_set_channel(uint8_t channel)
{
    if (channel < ZIGBLADE_CHANNEL_MIN || channel > ZIGBLADE_CHANNEL_MAX) {
        ESP_LOGE(TAG, "Invalid channel %d (must be %d-%d)",
                 channel, ZIGBLADE_CHANNEL_MIN, ZIGBLADE_CHANNEL_MAX);
        return ESP_ERR_INVALID_ARG;
    }

    esp_ieee802154_set_channel(channel);
    s_channel = channel;
    ESP_LOGD(TAG, "Channel set to %d", channel);
    return ESP_OK;
}

uint8_t zigblade_radio_get_channel(void)
{
    return s_channel;
}

esp_err_t zigblade_radio_start_receive(void)
{
    if (!s_initialized) {
        ESP_LOGE(TAG, "Radio not initialized");
        return ESP_ERR_INVALID_STATE;
    }

    esp_err_t err = esp_ieee802154_receive();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ieee802154_receive failed: %s", esp_err_to_name(err));
        return err;
    }

    s_receiving = true;
    ESP_LOGI(TAG, "RX started on channel %d", s_channel);
    return ESP_OK;
}

esp_err_t zigblade_radio_stop_receive(void)
{
    if (!s_receiving) {
        return ESP_OK;
    }

    esp_err_t err = esp_ieee802154_sleep();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ieee802154_sleep failed: %s", esp_err_to_name(err));
        return err;
    }

    s_receiving = false;
    ESP_LOGI(TAG, "RX stopped");
    return ESP_OK;
}

esp_err_t zigblade_radio_transmit(uint8_t *frame, uint8_t len)
{
    if (!s_initialized) {
        ESP_LOGE(TAG, "Radio not initialized");
        return ESP_ERR_INVALID_STATE;
    }
    if (frame == NULL || len == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    if (len > ZIGBLADE_MAX_FRAME_LEN + 1) { /* +1 for PHY length byte */
        ESP_LOGE(TAG, "Frame too long: %d bytes", len);
        return ESP_ERR_INVALID_ARG;
    }

    /* Clear the semaphore in case of stale signal */
    xSemaphoreTake(s_tx_done_sem, 0);

    /*
     * esp_ieee802154_transmit expects:
     *   frame[0] = PHY length (MPDU length including 2-byte FCS)
     *   frame[1..] = MPDU (MAC header + payload, without FCS)
     * CCA mode: 1 = CCA before transmit
     */
    esp_err_t err = esp_ieee802154_transmit(frame, false);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ieee802154_transmit failed: %s", esp_err_to_name(err));
        return err;
    }

    /* Wait for TX done (up to 100 ms) */
    if (xSemaphoreTake(s_tx_done_sem, pdMS_TO_TICKS(100)) != pdTRUE) {
        ESP_LOGW(TAG, "TX timeout");
        return ESP_ERR_TIMEOUT;
    }

    ESP_LOGD(TAG, "TX complete, %d bytes", len);
    return ESP_OK;
}

esp_err_t zigblade_radio_set_panid(uint16_t panid)
{
    esp_ieee802154_set_panid(panid);
    ESP_LOGD(TAG, "PAN ID set to 0x%04X", panid);
    return ESP_OK;
}

esp_err_t zigblade_radio_set_short_addr(uint16_t addr)
{
    esp_ieee802154_set_short_address(addr);
    ESP_LOGD(TAG, "Short address set to 0x%04X", addr);
    return ESP_OK;
}

esp_err_t zigblade_radio_set_ext_addr(uint8_t *addr)
{
    if (addr == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    esp_ieee802154_set_extended_address(addr);
    ESP_LOGD(TAG, "Extended address set");
    return ESP_OK;
}

esp_err_t zigblade_radio_register_rx_callback(zigblade_rx_callback_t cb)
{
    s_rx_cb = cb;
    ESP_LOGD(TAG, "RX callback %s", cb ? "registered" : "cleared");
    return ESP_OK;
}

bool zigblade_radio_is_receiving(void)
{
    return s_receiving;
}
