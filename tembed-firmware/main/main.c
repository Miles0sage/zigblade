#include <stdio.h>
#include <string.h>

#include "driver/uart.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "nvs_flash.h"

#include "input.h"
#include "uart_master.h"
#include "ui_tembed.h"
#include "web_ui.h"

static const char *TAG = "tembed_main";

#define H2_UART_TX_GPIO        43
#define H2_UART_RX_GPIO        44

static app_state_t s_state;
static QueueHandle_t s_input_queue;

static esp_err_t init_nvs(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    return ret;
}

static void set_status(const char *text)
{
    xSemaphoreTake(s_state.lock, portMAX_DELAY);
    snprintf(s_state.status_line, sizeof(s_state.status_line), "%s", text);
    xSemaphoreGive(s_state.lock);
}

static void reset_scan_results(void)
{
    xSemaphoreTake(s_state.lock, portMAX_DELAY);
    s_state.network_count = 0;
    xSemaphoreGive(s_state.lock);
}

static void clear_packets(void)
{
    xSemaphoreTake(s_state.lock, portMAX_DELAY);
    s_state.packet_count = 0;
    s_state.packet_head = 0;
    xSemaphoreGive(s_state.lock);
}

static void uart_event_handler(const uart_master_event_t *event, void *ctx)
{
    app_state_t *state = (app_state_t *)ctx;
    xSemaphoreTake(state->lock, portMAX_DELAY);

    switch (event->type) {
    case UART_MASTER_EVENT_SCAN_RESULT:
        if (state->network_count < APP_MAX_SCAN_RESULTS) {
            state->networks[state->network_count++] = event->data.scan_result;
        }
        snprintf(state->status_line, sizeof(state->status_line), "Scan results: %u", (unsigned)state->network_count);
        break;
    case UART_MASTER_EVENT_SCAN_COMPLETE:
        state->h2_state = UART_BRIDGE_STATE_IDLE;
        snprintf(state->status_line, sizeof(state->status_line), "Scan complete");
        break;
    case UART_MASTER_EVENT_PACKET:
        {
            size_t slot = state->packet_head % APP_MAX_PACKET_LOG;
            state->packets[slot] = event->data.packet;
            state->packets[slot].sequence = ++state->next_packet_sequence;
            state->packet_head = (state->packet_head + 1) % APP_MAX_PACKET_LOG;
            if (state->packet_count < APP_MAX_PACKET_LOG) {
                state->packet_count++;
            }
            state->total_packets++;
            snprintf(state->status_line, sizeof(state->status_line), "Packet %lu ch%u rssi%d",
                     (unsigned long)state->total_packets,
                     event->data.packet.channel,
                     event->data.packet.rssi);
        }
        break;
    case UART_MASTER_EVENT_KEY_FOUND:
        if (state->key_count < APP_MAX_KEYS) {
            state->keys[state->key_count] = event->data.key;
            state->keys[state->key_count].sequence = ++state->next_packet_sequence;
            state->key_count++;
        }
        snprintf(state->status_line, sizeof(state->status_line), "Captured transport key");
        break;
    case UART_MASTER_EVENT_STATUS:
        state->h2_state = (uart_bridge_state_t)event->data.status.state;
        state->current_channel = event->data.status.channel;
        state->total_packets = event->data.status.packet_count;
        break;
    case UART_MASTER_EVENT_ATTACK_PROGRESS:
        snprintf(state->status_line, sizeof(state->status_line), "Attack progress %u%%",
                 event->data.attack_progress.percent);
        break;
    case UART_MASTER_EVENT_ATTACK_COMPLETE:
        snprintf(state->status_line, sizeof(state->status_line), "Attack result %u",
                 event->data.attack_complete.result);
        break;
    case UART_MASTER_EVENT_ERROR:
        snprintf(state->status_line, sizeof(state->status_line), "H2 ERR %u %s",
                 event->data.error.code,
                 event->data.error.message);
        break;
    default:
        break;
    }

    xSemaphoreGive(state->lock);
}

static esp_err_t send_single_byte_cmd(uart_bridge_cmd_t cmd, uint8_t value)
{
    return uart_master_send_command(cmd, &value, 1);
}

static esp_err_t start_wifi_scan(void)
{
    if (!web_ui_is_running()) {
        return ESP_OK;
    }

    uint16_t ap_count = APP_MAX_WIFI_NETWORKS;
    wifi_ap_record_t aps[APP_MAX_WIFI_NETWORKS];
    memset(aps, 0, sizeof(aps));

    ESP_ERROR_CHECK(esp_wifi_scan_start(NULL, true));
    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&ap_count, aps));

    xSemaphoreTake(s_state.lock, portMAX_DELAY);
    s_state.wifi_network_count = (uint8_t)ap_count;
    for (uint16_t i = 0; i < ap_count; i++) {
        snprintf(s_state.wifi_networks[i], sizeof(s_state.wifi_networks[i]), "%s (%d dBm)",
                 (const char *)aps[i].ssid, aps[i].rssi);
    }
    xSemaphoreGive(s_state.lock);
    return ESP_OK;
}

static esp_err_t web_control_cb(const char *action, const char *arg, void *ctx)
{
    (void)arg;
    (void)ctx;

    if (strcmp(action, "scan_start") == 0) {
        reset_scan_results();
        return send_single_byte_cmd(CMD_SCAN_START, 0xFF);
    }
    if (strcmp(action, "scan_stop") == 0) {
        return uart_master_send_command(CMD_SCAN_STOP, NULL, 0);
    }
    if (strcmp(action, "sniff_start") == 0) {
        clear_packets();
        return send_single_byte_cmd(CMD_SNIFF_START, s_state.current_channel);
    }
    if (strcmp(action, "sniff_stop") == 0) {
        return uart_master_send_command(CMD_SNIFF_STOP, NULL, 0);
    }
    if (strcmp(action, "attack_start") == 0) {
        return ESP_ERR_NOT_SUPPORTED;
    }
    return ESP_ERR_INVALID_ARG;
}

static void enter_menu_screen(app_screen_t screen)
{
    xSemaphoreTake(s_state.lock, portMAX_DELAY);
    s_state.screen = screen;
    xSemaphoreGive(s_state.lock);
}

static void handle_menu_select(void)
{
    switch ((menu_item_t)s_state.menu_index) {
    case MENU_SCAN:
        enter_menu_screen(APP_SCREEN_SCAN);
        reset_scan_results();
        uart_master_send_command(CMD_SCAN_START, "\xFF", 1);
        set_status("Started Zigbee scan");
        break;
    case MENU_SNIFFER:
        enter_menu_screen(APP_SCREEN_SNIFFER);
        clear_packets();
        send_single_byte_cmd(CMD_SNIFF_START, s_state.current_channel);
        set_status("Started live sniffer");
        break;
    case MENU_ATTACKS:
        enter_menu_screen(APP_SCREEN_ATTACKS);
        set_status("Attack features disabled in safe build");
        break;
    case MENU_SUBGHZ:
        enter_menu_screen(APP_SCREEN_SUBGHZ);
        set_status("CC1101 tools placeholder ready");
        break;
    case MENU_WIFI:
        enter_menu_screen(APP_SCREEN_WIFI);
        set_status("Web UI AP required for WiFi scan");
        break;
    case MENU_SETTINGS:
        enter_menu_screen(APP_SCREEN_SETTINGS);
        set_status("Rotate to adjust brightness");
        break;
    case MENU_WEB_UI:
        enter_menu_screen(APP_SCREEN_WEB_UI);
        if (!web_ui_is_running()) {
            ESP_ERROR_CHECK(web_ui_start(&s_state, web_control_cb, NULL));
            xSemaphoreTake(s_state.lock, portMAX_DELAY);
            s_state.web_ui_active = true;
            xSemaphoreGive(s_state.lock);
            start_wifi_scan();
        }
        set_status("Web UI online at 192.168.4.1");
        break;
    default:
        break;
    }
}

static void handle_input_event(const input_event_t *event)
{
    xSemaphoreTake(s_state.lock, portMAX_DELAY);
    app_screen_t screen = s_state.screen;
    xSemaphoreGive(s_state.lock);

    if (screen == APP_SCREEN_MENU) {
        if (event->type == INPUT_EVENT_ROTATE_LEFT && s_state.menu_index > 0) {
            s_state.menu_index--;
        } else if (event->type == INPUT_EVENT_ROTATE_RIGHT && s_state.menu_index + 1 < MENU_COUNT) {
            s_state.menu_index++;
        } else if (event->type == INPUT_EVENT_BUTTON_SHORT) {
            handle_menu_select();
        }
        return;
    }

    if (screen == APP_SCREEN_SETTINGS) {
        if (event->type == INPUT_EVENT_ROTATE_LEFT && s_state.brightness > 16) {
            s_state.brightness -= 16;
            ui_tembed_set_backlight(s_state.brightness);
        } else if (event->type == INPUT_EVENT_ROTATE_RIGHT && s_state.brightness < 240) {
            s_state.brightness += 16;
            ui_tembed_set_backlight(s_state.brightness);
        }
    }

    if (event->type == INPUT_EVENT_BUTTON_LONG) {
        enter_menu_screen(APP_SCREEN_MENU);
        set_status("Returned to menu");
    }
}

static void poll_status_task(void *arg)
{
    (void)arg;

    while (true) {
        uart_master_send_command(CMD_GET_STATUS, NULL, 0);
        if (web_ui_is_running()) {
            start_wifi_scan();
        }
        vTaskDelay(pdMS_TO_TICKS(1500));
    }
}

void app_main(void)
{
    ESP_LOGI(TAG, "ZigBlade T-Embed companion firmware");

    ESP_ERROR_CHECK(init_nvs());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    memset(&s_state, 0, sizeof(s_state));
    s_state.lock = xSemaphoreCreateMutex();
    s_state.screen = APP_SCREEN_SPLASH;
    s_state.current_channel = 15;
    s_state.tx_power_dbm = 0;
    s_state.brightness = 255;
    snprintf(s_state.status_line, sizeof(s_state.status_line), "Booting T-Embed");

    s_input_queue = xQueueCreate(16, sizeof(input_event_t));
    ESP_ERROR_CHECK(ui_tembed_init());
    ESP_ERROR_CHECK(input_init(s_input_queue));
    ESP_ERROR_CHECK(uart_master_init(H2_UART_TX_GPIO, H2_UART_RX_GPIO, UART_MASTER_BAUD, uart_event_handler, &s_state));

    xTaskCreate(poll_status_task, "status_poll", 3072, NULL, 5, NULL);

    vTaskDelay(pdMS_TO_TICKS(1300));
    s_state.screen = APP_SCREEN_MENU;
    set_status("Ready");

    while (true) {
        input_event_t event;
        if (xQueueReceive(s_input_queue, &event, pdMS_TO_TICKS(40)) == pdTRUE) {
            handle_input_event(&event);
        }
        ui_tembed_render(&s_state);
    }
}
