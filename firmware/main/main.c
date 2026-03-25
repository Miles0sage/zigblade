/*
 * ZigBlade firmware entry point.
 *
 * Shared promiscuous capture is owned by the Zigbee sniffer and fed into
 * the Thread scanner/sniffer and Matter monitor so the single ESP32-H2
 * 802.15.4 radio can service all protocol analyzers concurrently.
 */

#include <stdio.h>
#include <inttypes.h>

#include "esp_err.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/spi_master.h"
#include "driver/sdspi_host.h"
#include "esp_vfs_fat.h"
#include "led_strip.h"
#include "sdmmc_cmd.h"

#include "display.h"
#include "menu.h"
#include "ieee802154_hal.h"
#include "matter_monitor.h"
#include "thread_scanner.h"
#include "thread_sniffer.h"
#include "zigbee_injector.h"
#include "zigbee_sniffer.h"

static const char *TAG = "zigblade";

#define UI_TASK_STACK_SIZE        (6 * 1024)
#define ZIGBEE_TASK_STACK_SIZE    (6 * 1024)
#define THREAD_TASK_STACK_SIZE    (5 * 1024)
#define MATTER_TASK_STACK_SIZE    (5 * 1024)

#define UI_TASK_PRIORITY          3
#define ZIGBEE_TASK_PRIORITY      6
#define THREAD_TASK_PRIORITY      5
#define MATTER_TASK_PRIORITY      4

#define PIN_SPI_MOSI              CONFIG_ZIGBLADE_SPI_MOSI_PIN
#define PIN_SPI_MISO              CONFIG_ZIGBLADE_SPI_MISO_PIN
#define PIN_SPI_CLK               CONFIG_ZIGBLADE_SPI_CLK_PIN
#define PIN_SD_CS                 CONFIG_ZIGBLADE_SD_CS_PIN
#define PIN_LED                   CONFIG_ZIGBLADE_LED_PIN

static sdmmc_card_t *g_sd_card = NULL;
static led_strip_handle_t g_led_strip = NULL;

static esp_err_t init_nvs(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    return ret;
}

static esp_err_t init_spi_bus(void)
{
    const spi_bus_config_t bus_cfg = {
        .mosi_io_num = PIN_SPI_MOSI,
        .miso_io_num = PIN_SPI_MISO,
        .sclk_io_num = PIN_SPI_CLK,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = 4096,
    };

    return spi_bus_initialize(SPI2_HOST, &bus_cfg, SPI_DMA_CH_AUTO);
}

static esp_err_t init_sd_card(void)
{
    const esp_vfs_fat_sdmmc_mount_config_t mount_cfg = {
        .format_if_mount_failed = false,
        .max_files = 6,
        .allocation_unit_size = 16 * 1024,
    };

    sdmmc_host_t host = SDSPI_HOST_DEFAULT();
    const sdspi_device_config_t slot_cfg = {
        .host_id = SPI2_HOST,
        .gpio_cs = PIN_SD_CS,
        .gpio_cd = SDSPI_SLOT_NO_CD,
        .gpio_wp = SDSPI_SLOT_NO_WP,
        .gpio_int = SDSPI_SLOT_NO_INT,
    };

    esp_err_t ret = esp_vfs_fat_sdspi_mount(CONFIG_ZIGBLADE_PCAP_MOUNT_POINT,
                                            &host,
                                            &slot_cfg,
                                            &mount_cfg,
                                            &g_sd_card);
    if (ret == ESP_OK) {
        ESP_LOGI(TAG, "SD card mounted at %s", CONFIG_ZIGBLADE_PCAP_MOUNT_POINT);
    } else {
        ESP_LOGW(TAG, "SD card unavailable: %s", esp_err_to_name(ret));
    }

    return ret;
}

static esp_err_t init_led(void)
{
    const led_strip_config_t strip_cfg = {
        .strip_gpio_num = PIN_LED,
        .max_leds = 1,
        .led_model = LED_MODEL_WS2812,
    };
    const led_strip_rmt_config_t rmt_cfg = {
        .clk_src = RMT_CLK_SRC_DEFAULT,
        .resolution_hz = 10 * 1000 * 1000,
    };

    esp_err_t ret = led_strip_new_rmt_device(&strip_cfg, &rmt_cfg, &g_led_strip);
    if (ret == ESP_OK) {
        led_strip_clear(g_led_strip);
    }
    return ret;
}

static void led_set_color(uint8_t r, uint8_t g, uint8_t b)
{
    if (g_led_strip == NULL) {
        return;
    }

    led_strip_set_pixel(g_led_strip, 0, r, g, b);
    led_strip_refresh(g_led_strip);
}

static void protocol_dispatch_callback(const captured_packet_t *pkt)
{
    if (pkt == NULL) {
        return;
    }

    thread_scan_process_packet(pkt->parsed.raw,
                               pkt->parsed.raw_len,
                               pkt->rssi,
                               pkt->channel,
                               pkt->timestamp_us);
    thread_sniffer_process_packet(pkt->parsed.raw,
                                  pkt->parsed.raw_len,
                                  pkt->rssi,
                                  pkt->channel,
                                  pkt->timestamp_us);
    matter_monitor_process_packet(pkt->parsed.raw,
                                  pkt->parsed.raw_len,
                                  pkt->rssi,
                                  pkt->channel,
                                  pkt->timestamp_us);
}

static void ui_task(void *arg)
{
    (void)arg;

    ESP_ERROR_CHECK(display_init());
    ESP_ERROR_CHECK(button_init());
    ESP_ERROR_CHECK(menu_init());
    menu_render();

    for (;;) {
        button_event_t evt;
        if (button_get_event(&evt, 50)) {
            menu_handle_input(evt.button, evt.type);
            menu_render();
        }
        vTaskDelay(pdMS_TO_TICKS(20));
    }
}

static void zigbee_task(void *arg)
{
    (void)arg;

    ESP_ERROR_CHECK(zigbee_injector_init());
    ESP_ERROR_CHECK(zigbee_sniffer_register_callback(protocol_dispatch_callback));
    ESP_ERROR_CHECK(zigbee_sniffer_start_auto_hop());

    if (g_sd_card != NULL) {
        char path[96];
        snprintf(path, sizeof(path), "%s/zigbee_capture.pcap", CONFIG_ZIGBLADE_PCAP_MOUNT_POINT);
        zigbee_sniffer_enable_pcap(path);
    }

    for (;;) {
        zigbee_sniffer_stats_t stats;
        if (zigbee_sniffer_get_stats(&stats) == ESP_OK) {
            ESP_LOGI(TAG,
                     "Zigbee capture: pkts=%" PRIu32 " pps=%" PRIu32
                     " uniq=%" PRIu32 " zb=%" PRIu32 " th=%" PRIu32
                     " matter=%" PRIu32 " ch=%u%s",
                     stats.total_packets,
                     stats.packets_per_sec,
                     stats.unique_devices,
                     stats.zigbee_packets,
                     stats.thread_packets,
                     stats.matter_packets,
                     stats.current_channel,
                     stats.channel_hopping ? " hop" : "");
        }

        led_set_color(0, 0, 16);
        vTaskDelay(pdMS_TO_TICKS(900));
        led_set_color(0, 0, 0);
        vTaskDelay(pdMS_TO_TICKS(100));
    }
}

static void thread_task(void *arg)
{
    (void)arg;

    ESP_ERROR_CHECK(thread_scan_start());
    ESP_ERROR_CHECK(thread_sniffer_start());
    if (g_sd_card != NULL) {
        char path[96];
        snprintf(path, sizeof(path), "%s/thread_capture.pcap", CONFIG_ZIGBLADE_PCAP_MOUNT_POINT);
        thread_sniffer_enable_pcap(path);
    }

    for (;;) {
        const thread_scan_result_t *scan = thread_scan_get_results();
        thread_sniffer_stats_t stats;
        thread_credentials_t creds;
        thread_sniffer_get_stats(&stats);
        thread_sniffer_get_credentials(&creds);

        ESP_LOGI(TAG,
                 "Thread monitor: nets=%u mle=%" PRIu32 " pkts=%" PRIu32
                 " pps=%" PRIu32 " creds=%s",
                 scan->count,
                 scan->mle_advertisements,
                 stats.total_packets,
                 stats.packets_per_sec,
                 creds.commissioning_seen ? "seen" : "none");
        vTaskDelay(pdMS_TO_TICKS(2000));
    }
}

static void matter_task(void *arg)
{
    (void)arg;

    ESP_ERROR_CHECK(matter_monitor_start());

    for (;;) {
        matter_monitor_stats_t stats;
        matter_monitor_get_stats(&stats);
        ESP_LOGI(TAG,
                 "Matter monitor: pkts=%" PRIu32 " sessions=%" PRIu32
                 " deedos=%" PRIu32 " ch=%u",
                 stats.matter_over_thread_packets,
                 stats.active_sessions,
                 stats.deedos_candidates,
                 stats.last_channel);
        vTaskDelay(pdMS_TO_TICKS(3000));
    }
}

void app_main(void)
{
    ESP_LOGI(TAG, "=========================================");
    ESP_LOGI(TAG, " ZigBlade — Zigbee/Thread/Matter Tool");
    ESP_LOGI(TAG, " Target: ESP32-H2");
    ESP_LOGI(TAG, "=========================================");

    ESP_ERROR_CHECK(init_nvs());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    ESP_ERROR_CHECK(init_spi_bus());
    init_sd_card();
    ESP_ERROR_CHECK(init_led());
    ESP_ERROR_CHECK(zigblade_radio_init());

    led_set_color(0, 24, 0);
    vTaskDelay(pdMS_TO_TICKS(150));
    led_set_color(0, 0, 0);

    xTaskCreate(ui_task, "ui_task", UI_TASK_STACK_SIZE, NULL, UI_TASK_PRIORITY, NULL);
    xTaskCreate(zigbee_task, "zigbee_task", ZIGBEE_TASK_STACK_SIZE, NULL, ZIGBEE_TASK_PRIORITY, NULL);
    xTaskCreate(thread_task, "thread_task", THREAD_TASK_STACK_SIZE, NULL, THREAD_TASK_PRIORITY, NULL);
    xTaskCreate(matter_task, "matter_task", MATTER_TASK_STACK_SIZE, NULL, MATTER_TASK_PRIORITY, NULL);
}
