#include "uart_master.h"

#include <inttypes.h>
#include <string.h>

#include "driver/uart.h"
#include "esp_log.h"
#include "freertos/task.h"

static const char *TAG = "uart_master";

#define UART_MASTER_PORT              UART_NUM_1
#define UART_MASTER_RX_BUF_SIZE       2048

typedef struct {
    uart_master_event_cb_t event_cb;
    void *event_ctx;
    SemaphoreHandle_t tx_lock;
    bool initialized;
    uint8_t rx_buf[UART_MASTER_RX_BUF_SIZE];
    size_t rx_len;
} uart_master_ctx_t;

static uart_master_ctx_t s_ctx;

static uint16_t rd_le16(const uint8_t *buf)
{
    return (uint16_t)buf[0] | ((uint16_t)buf[1] << 8);
}

static uint32_t rd_le32(const uint8_t *buf)
{
    return (uint32_t)buf[0] |
           ((uint32_t)buf[1] << 8) |
           ((uint32_t)buf[2] << 16) |
           ((uint32_t)buf[3] << 24);
}

static void wr_le16(uint8_t *buf, uint16_t value)
{
    buf[0] = (uint8_t)(value & 0xFF);
    buf[1] = (uint8_t)((value >> 8) & 0xFF);
}

uint8_t uart_master_crc8(const uint8_t *data, size_t len)
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

static void emit_event(const uart_master_event_t *event)
{
    if (s_ctx.event_cb != NULL) {
        s_ctx.event_cb(event, s_ctx.event_ctx);
    }
}

static void decode_frame(uint8_t msg_id, const uint8_t *payload, uint16_t payload_len)
{
    uart_master_event_t event = { 0 };

    switch (msg_id) {
    case RSP_SCAN_RESULT:
        if (payload_len == sizeof(zb_network_info_t)) {
            event.type = UART_MASTER_EVENT_SCAN_RESULT;
            memcpy(&event.data.scan_result, payload, sizeof(zb_network_info_t));
            emit_event(&event);
        }
        break;
    case RSP_SCAN_COMPLETE:
        event.type = UART_MASTER_EVENT_SCAN_COMPLETE;
        emit_event(&event);
        break;
    case RSP_PACKET:
        if (payload_len >= 2) {
            event.type = UART_MASTER_EVENT_PACKET;
            event.data.packet.channel = payload[0];
            event.data.packet.rssi = (int8_t)payload[1];
            event.data.packet.len = payload_len - 2;
            if (event.data.packet.len > APP_PACKET_PREVIEW_LEN) {
                event.data.packet.len = APP_PACKET_PREVIEW_LEN;
            }
            memcpy(event.data.packet.data, payload + 2, event.data.packet.len);
            emit_event(&event);
        }
        break;
    case RSP_KEY_FOUND:
        if (payload_len == 16) {
            event.type = UART_MASTER_EVENT_KEY_FOUND;
            memcpy(event.data.key.key, payload, 16);
            emit_event(&event);
        }
        break;
    case RSP_STATUS:
        if (payload_len >= 6) {
            event.type = UART_MASTER_EVENT_STATUS;
            event.data.status.state = payload[0];
            event.data.status.channel = payload[1];
            event.data.status.packet_count = rd_le32(payload + 2);
            emit_event(&event);
        }
        break;
    case RSP_ATTACK_PROGRESS:
        if (payload_len >= 5) {
            event.type = UART_MASTER_EVENT_ATTACK_PROGRESS;
            event.data.attack_progress.percent = payload[0];
            event.data.attack_progress.packets_sent = rd_le32(payload + 1);
            emit_event(&event);
        }
        break;
    case RSP_ATTACK_COMPLETE:
        if (payload_len >= 1) {
            event.type = UART_MASTER_EVENT_ATTACK_COMPLETE;
            event.data.attack_complete.result = payload[0];
            emit_event(&event);
        }
        break;
    case RSP_ERROR:
        if (payload_len >= 2) {
            size_t msg_len = payload_len - 2;
            if (msg_len >= sizeof(event.data.error.message)) {
                msg_len = sizeof(event.data.error.message) - 1;
            }
            event.type = UART_MASTER_EVENT_ERROR;
            event.data.error.code = rd_le16(payload);
            memcpy(event.data.error.message, payload + 2, msg_len);
            event.data.error.message[msg_len] = '\0';
            emit_event(&event);
        }
        break;
    default:
        ESP_LOGW(TAG, "Unhandled response 0x%02X len=%u", msg_id, payload_len);
        break;
    }
}

static void process_rx_buffer(void)
{
    while (s_ctx.rx_len >= 6) {
        size_t start = 0;
        while (start + 1 < s_ctx.rx_len &&
               !(s_ctx.rx_buf[start] == UART_MASTER_MAGIC_0 &&
                 s_ctx.rx_buf[start + 1] == UART_MASTER_MAGIC_1)) {
            start++;
        }
        if (start > 0) {
            memmove(s_ctx.rx_buf, s_ctx.rx_buf + start, s_ctx.rx_len - start);
            s_ctx.rx_len -= start;
        }
        if (s_ctx.rx_len < 6) {
            return;
        }

        uint16_t payload_len = rd_le16(&s_ctx.rx_buf[3]);
        size_t frame_len = 5U + payload_len + 1U;
        if (payload_len > UART_MASTER_MAX_PAYLOAD) {
            ESP_LOGW(TAG, "Discarding invalid payload len=%u", payload_len);
            memmove(s_ctx.rx_buf, s_ctx.rx_buf + 2, s_ctx.rx_len - 2);
            s_ctx.rx_len -= 2;
            continue;
        }
        if (s_ctx.rx_len < frame_len) {
            return;
        }

        uint8_t crc = uart_master_crc8(s_ctx.rx_buf, frame_len - 1);
        if (crc == s_ctx.rx_buf[frame_len - 1]) {
            decode_frame(s_ctx.rx_buf[2], s_ctx.rx_buf + 5, payload_len);
        } else {
            ESP_LOGW(TAG, "CRC mismatch for msg 0x%02X", s_ctx.rx_buf[2]);
        }

        memmove(s_ctx.rx_buf, s_ctx.rx_buf + frame_len, s_ctx.rx_len - frame_len);
        s_ctx.rx_len -= frame_len;
    }
}

static void uart_master_task(void *arg)
{
    (void)arg;
    uint8_t tmp[128];

    while (true) {
        int read = uart_read_bytes(UART_MASTER_PORT, tmp, sizeof(tmp), pdMS_TO_TICKS(25));
        if (read > 0) {
            if (s_ctx.rx_len + (size_t)read > sizeof(s_ctx.rx_buf)) {
                s_ctx.rx_len = 0;
            }
            memcpy(s_ctx.rx_buf + s_ctx.rx_len, tmp, (size_t)read);
            s_ctx.rx_len += (size_t)read;
            process_rx_buffer();
        }
    }
}

esp_err_t uart_master_init(int tx_pin,
                           int rx_pin,
                           uint32_t baud,
                           uart_master_event_cb_t event_cb,
                           void *event_ctx)
{
    uart_config_t cfg = {
        .baud_rate = (int)baud,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };

    memset(&s_ctx, 0, sizeof(s_ctx));
    s_ctx.tx_lock = xSemaphoreCreateMutex();
    s_ctx.event_cb = event_cb;
    s_ctx.event_ctx = event_ctx;
    if (s_ctx.tx_lock == NULL) {
        return ESP_ERR_NO_MEM;
    }

    ESP_ERROR_CHECK(uart_driver_install(UART_MASTER_PORT, UART_MASTER_RX_BUF_SIZE, 0, 0, NULL, 0));
    ESP_ERROR_CHECK(uart_param_config(UART_MASTER_PORT, &cfg));
    ESP_ERROR_CHECK(uart_set_pin(UART_MASTER_PORT, tx_pin, rx_pin, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));

    s_ctx.initialized = true;
    xTaskCreate(uart_master_task, "uart_master", 4096, NULL, 8, NULL);
    ESP_LOGI(TAG, "UART master ready on UART1 TX=%d RX=%d baud=%" PRIu32, tx_pin, rx_pin, baud);
    return ESP_OK;
}

esp_err_t uart_master_send_command(uart_bridge_cmd_t cmd, const void *payload, uint16_t payload_len)
{
    if (!s_ctx.initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    if (payload_len > UART_MASTER_MAX_PAYLOAD) {
        return ESP_ERR_INVALID_SIZE;
    }

    uint8_t frame[5 + UART_MASTER_MAX_PAYLOAD + 1];
    frame[0] = UART_MASTER_MAGIC_0;
    frame[1] = UART_MASTER_MAGIC_1;
    frame[2] = (uint8_t)cmd;
    wr_le16(&frame[3], payload_len);
    if (payload_len > 0 && payload != NULL) {
        memcpy(&frame[5], payload, payload_len);
    }
    frame[5 + payload_len] = uart_master_crc8(frame, 5 + payload_len);

    xSemaphoreTake(s_ctx.tx_lock, portMAX_DELAY);
    int written = uart_write_bytes(UART_MASTER_PORT, (const char *)frame, 6 + payload_len);
    uart_wait_tx_done(UART_MASTER_PORT, pdMS_TO_TICKS(50));
    xSemaphoreGive(s_ctx.tx_lock);

    return (written == (int)(6 + payload_len)) ? ESP_OK : ESP_FAIL;
}
