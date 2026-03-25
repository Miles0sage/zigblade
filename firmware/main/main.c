/*
 * ZigBlade — Zigbee / IEEE 802.15.4 Security Testing Tool
 * Entry point: initialises all subsystems and launches FreeRTOS tasks.
 *
 * Target: ESP32-H2  |  Framework: ESP-IDF >= 5.1
 */

#include <stdio.h>
#include <string.h>

/* ESP-IDF core */
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "esp_log.h"
#include "esp_err.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "esp_event.h"

/* Drivers */
#include "driver/gpio.h"
#include "driver/spi_master.h"
#include "driver/i2c_master.h"

/* SD card (SPI mode) */
#include "esp_vfs_fat.h"
#include "sdmmc_cmd.h"
#include "driver/sdspi_host.h"

/* LED strip (WS2812B via RMT) */
#include "led_strip.h"

/* IEEE 802.15.4 */
#include "esp_ieee802154.h"

/* ---------------------------------------------------------------------------
 * Constants
 * --------------------------------------------------------------------------- */

static const char *TAG = "zigblade";

/* Task stack sizes */
#define UI_TASK_STACK_SIZE       (8 * 1024)
#define SCANNER_TASK_STACK_SIZE  (8 * 1024)
#define SNIFFER_TASK_STACK_SIZE  (8 * 1024)

/* Task priorities (higher number = higher priority) */
#define UI_TASK_PRIORITY         3
#define SCANNER_TASK_PRIORITY    5
#define SNIFFER_TASK_PRIORITY    6

/* Button debounce (ms) */
#define BTN_DEBOUNCE_MS          50

/* GPIO pin definitions from Kconfig */
#define PIN_I2C_SDA   CONFIG_ZIGBLADE_I2C_SDA_PIN
#define PIN_I2C_SCL   CONFIG_ZIGBLADE_I2C_SCL_PIN
#define PIN_SPI_MOSI  CONFIG_ZIGBLADE_SPI_MOSI_PIN
#define PIN_SPI_MISO  CONFIG_ZIGBLADE_SPI_MISO_PIN
#define PIN_SPI_CLK   CONFIG_ZIGBLADE_SPI_CLK_PIN
#define PIN_SD_CS     CONFIG_ZIGBLADE_SD_CS_PIN
#define PIN_BTN_UP    CONFIG_ZIGBLADE_BTN_UP_PIN
#define PIN_BTN_DOWN  CONFIG_ZIGBLADE_BTN_DOWN_PIN
#define PIN_BTN_SEL   CONFIG_ZIGBLADE_BTN_SELECT_PIN
#define PIN_BTN_BACK  CONFIG_ZIGBLADE_BTN_BACK_PIN
#define PIN_LED       CONFIG_ZIGBLADE_LED_PIN

/* ---------------------------------------------------------------------------
 * Global handles
 * --------------------------------------------------------------------------- */

static spi_device_handle_t  g_spi_display_handle;
static i2c_master_bus_handle_t g_i2c_bus_handle;
static sdmmc_card_t        *g_sd_card;
static led_strip_handle_t   g_led_strip;

/* Button event queue shared with the UI task */
static QueueHandle_t        g_btn_evt_queue;

/* ---------------------------------------------------------------------------
 * Button ISR
 * --------------------------------------------------------------------------- */

typedef enum {
    BTN_EVT_UP = 0,
    BTN_EVT_DOWN,
    BTN_EVT_SELECT,
    BTN_EVT_BACK,
} btn_event_t;

static void IRAM_ATTR gpio_isr_handler(void *arg)
{
    btn_event_t evt = (btn_event_t)(uintptr_t)arg;
    xQueueSendFromISR(g_btn_evt_queue, &evt, NULL);
}

/* ---------------------------------------------------------------------------
 * Subsystem init helpers
 * --------------------------------------------------------------------------- */

static esp_err_t init_nvs(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES ||
        ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "Erasing NVS flash and re-initialising");
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    return ret;
}

static esp_err_t init_ieee802154(void)
{
    ESP_LOGI(TAG, "Initialising IEEE 802.15.4 radio");
    ESP_ERROR_CHECK(esp_ieee802154_enable());
    ESP_ERROR_CHECK(esp_ieee802154_set_channel(CONFIG_ZIGBLADE_DEFAULT_CHANNEL));
    ESP_ERROR_CHECK(esp_ieee802154_set_promiscuous(true));
    esp_ieee802154_set_rx_when_idle(true);

    ESP_LOGI(TAG, "802.15.4 radio on channel %d (promiscuous)",
             CONFIG_ZIGBLADE_DEFAULT_CHANNEL);
    return ESP_OK;
}

static esp_err_t init_spi_bus(void)
{
    ESP_LOGI(TAG, "Initialising SPI bus (MOSI=%d CLK=%d MISO=%d)",
             PIN_SPI_MOSI, PIN_SPI_CLK, PIN_SPI_MISO);

    const spi_bus_config_t bus_cfg = {
        .mosi_io_num   = PIN_SPI_MOSI,
        .miso_io_num   = PIN_SPI_MISO,
        .sclk_io_num   = PIN_SPI_CLK,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = 4096,
    };

    return spi_bus_initialize(SPI2_HOST, &bus_cfg, SPI_DMA_CH_AUTO);
}

static esp_err_t init_i2c_bus(void)
{
    ESP_LOGI(TAG, "Initialising I2C bus (SDA=%d SCL=%d)", PIN_I2C_SDA, PIN_I2C_SCL);

    const i2c_master_bus_config_t bus_cfg = {
        .i2c_port  = I2C_NUM_0,
        .sda_io_num = PIN_I2C_SDA,
        .scl_io_num = PIN_I2C_SCL,
        .clk_source = I2C_CLK_SRC_DEFAULT,
        .glitch_ignore_cnt = 7,
        .flags.enable_internal_pullup = true,
    };

    return i2c_new_master_bus(&bus_cfg, &g_i2c_bus_handle);
}

static esp_err_t init_sd_card(void)
{
    ESP_LOGI(TAG, "Mounting SD card at %s (CS=%d)",
             CONFIG_ZIGBLADE_PCAP_MOUNT_POINT, PIN_SD_CS);

    const esp_vfs_fat_sdmmc_mount_config_t mount_cfg = {
        .format_if_mount_failed = true,
        .max_files              = 5,
        .allocation_unit_size   = 16 * 1024,
    };

    sdmmc_host_t host = SDSPI_HOST_DEFAULT();

    const sdspi_device_config_t slot_cfg = {
        .host_id   = SPI2_HOST,
        .gpio_cs   = PIN_SD_CS,
        .gpio_cd   = SDSPI_SLOT_NO_CD,
        .gpio_wp   = SDSPI_SLOT_NO_WP,
        .gpio_int  = SDSPI_SLOT_NO_INT,
    };

    esp_err_t ret = esp_vfs_fat_sdspi_mount(
        CONFIG_ZIGBLADE_PCAP_MOUNT_POINT, &host, &slot_cfg,
        &mount_cfg, &g_sd_card);

    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "SD card mount failed (%s) — PCAP capture disabled",
                 esp_err_to_name(ret));
    } else {
        sdmmc_card_print_info(stdout, g_sd_card);
    }

    return ret;
}

static esp_err_t init_buttons(void)
{
    ESP_LOGI(TAG, "Configuring navigation buttons");

    g_btn_evt_queue = xQueueCreate(16, sizeof(btn_event_t));
    if (g_btn_evt_queue == NULL) {
        ESP_LOGE(TAG, "Failed to create button event queue");
        return ESP_ERR_NO_MEM;
    }

    const int btn_pins[] = {PIN_BTN_UP, PIN_BTN_DOWN, PIN_BTN_SEL, PIN_BTN_BACK};
    const btn_event_t btn_ids[] = {BTN_EVT_UP, BTN_EVT_DOWN, BTN_EVT_SELECT, BTN_EVT_BACK};

    /* Install GPIO ISR service once */
    esp_err_t ret = gpio_install_isr_service(0);
    if (ret != ESP_OK && ret != ESP_ERR_INVALID_STATE) {
        return ret;
    }

    for (int i = 0; i < 4; i++) {
        const gpio_config_t io_cfg = {
            .pin_bit_mask = (1ULL << btn_pins[i]),
            .mode         = GPIO_MODE_INPUT,
            .pull_up_en   = GPIO_PULLUP_ENABLE,
            .pull_down_en = GPIO_PULLDOWN_DISABLE,
            .intr_type    = GPIO_INTR_NEGEDGE,
        };
        ESP_ERROR_CHECK(gpio_config(&io_cfg));
        ESP_ERROR_CHECK(gpio_isr_handler_add(
            btn_pins[i], gpio_isr_handler, (void *)(uintptr_t)btn_ids[i]));
    }

    return ESP_OK;
}

static esp_err_t init_led(void)
{
    ESP_LOGI(TAG, "Initialising WS2812B LED on GPIO %d", PIN_LED);

    const led_strip_config_t strip_cfg = {
        .strip_gpio_num   = PIN_LED,
        .max_leds         = 1,
        .led_model        = LED_MODEL_WS2812,
    };

    const led_strip_rmt_config_t rmt_cfg = {
        .clk_src        = RMT_CLK_SRC_DEFAULT,
        .resolution_hz  = 10 * 1000 * 1000,  /* 10 MHz */
    };

    esp_err_t ret = led_strip_new_rmt_device(&strip_cfg, &rmt_cfg, &g_led_strip);
    if (ret == ESP_OK) {
        /* Turn LED off initially */
        led_strip_clear(g_led_strip);
    }
    return ret;
}

/* ---------------------------------------------------------------------------
 * LED status helper
 * --------------------------------------------------------------------------- */

static void led_set_color(uint8_t r, uint8_t g, uint8_t b)
{
    if (g_led_strip == NULL) return;
    led_strip_set_pixel(g_led_strip, 0, r, g, b);
    led_strip_refresh(g_led_strip);
}

/* ---------------------------------------------------------------------------
 * FreeRTOS tasks
 * --------------------------------------------------------------------------- */

/**
 * UI task — drives the OLED display and reads button events.
 */
static void ui_task(void *pv)
{
    ESP_LOGI(TAG, "ui_task started");
    btn_event_t evt;

    for (;;) {
        if (xQueueReceive(g_btn_evt_queue, &evt, pdMS_TO_TICKS(100)) == pdTRUE) {
            switch (evt) {
            case BTN_EVT_UP:
                ESP_LOGI(TAG, "BTN: UP");
                break;
            case BTN_EVT_DOWN:
                ESP_LOGI(TAG, "BTN: DOWN");
                break;
            case BTN_EVT_SELECT:
                ESP_LOGI(TAG, "BTN: SELECT");
                break;
            case BTN_EVT_BACK:
                ESP_LOGI(TAG, "BTN: BACK");
                break;
            }
        }

        /* TODO: Render current menu / status screen on OLED via g_i2c_bus_handle */
        vTaskDelay(pdMS_TO_TICKS(BTN_DEBOUNCE_MS));
    }
}

/**
 * Scanner task — actively scans 802.15.4 channels and catalogues networks.
 */
static void scanner_task(void *pv)
{
    ESP_LOGI(TAG, "scanner_task started");

    uint8_t channel = CONFIG_ZIGBLADE_DEFAULT_CHANNEL;

    for (;;) {
        /* Cycle through channels 11-26 */
        ESP_LOGI(TAG, "Scanning channel %d", channel);
        esp_ieee802154_set_channel(channel);
        esp_ieee802154_receive();

        /* Dwell on each channel */
        vTaskDelay(pdMS_TO_TICKS(500));

        channel++;
        if (channel > 26) {
            channel = 11;
        }
    }
}

/**
 * Sniffer task — captures raw 802.15.4 frames and writes PCAP to SD card.
 */
static void sniffer_task(void *pv)
{
    ESP_LOGI(TAG, "sniffer_task started");

    /* Open a PCAP file on the SD card if mounted */
    FILE *pcap_fp = NULL;
    if (g_sd_card != NULL) {
        char path[64];
        snprintf(path, sizeof(path), "%s/capture.pcap",
                 CONFIG_ZIGBLADE_PCAP_MOUNT_POINT);
        pcap_fp = fopen(path, "wb");
        if (pcap_fp != NULL) {
            /* Write PCAP global header (linktype 195 = IEEE 802.15.4) */
            const uint32_t pcap_hdr[] = {
                0xA1B2C3D4, /* magic */
                0x00040002, /* version 2.4 */
                0x00000000, /* thiszone */
                0x00000000, /* sigfigs */
                0x0000FFFF, /* snaplen */
                0x000000C3, /* linktype: IEEE 802.15.4 */
            };
            fwrite(pcap_hdr, sizeof(pcap_hdr), 1, pcap_fp);
            fflush(pcap_fp);
            ESP_LOGI(TAG, "PCAP file opened: %s", path);
        } else {
            ESP_LOGW(TAG, "Failed to open PCAP file");
        }
    }

    for (;;) {
        /*
         * In a full implementation this task would register an
         * esp_ieee802154_receive_done_cb() callback to receive frames
         * from the radio, then write each frame into the PCAP file
         * with a proper record header (timestamp + length).
         *
         * For now we yield and let the radio ISR accumulate frames.
         */
        led_set_color(0, 0, 32);   /* dim blue = listening */
        vTaskDelay(pdMS_TO_TICKS(100));
        led_set_color(0, 0, 0);
        vTaskDelay(pdMS_TO_TICKS(900));
    }

    /* Unreachable, but good practice */
    if (pcap_fp != NULL) {
        fclose(pcap_fp);
    }
}

/* ---------------------------------------------------------------------------
 * app_main — entry point
 * --------------------------------------------------------------------------- */

void app_main(void)
{
    ESP_LOGI(TAG, "=========================================");
    ESP_LOGI(TAG, " ZigBlade — 802.15.4 Security Tool");
    ESP_LOGI(TAG, " Target: ESP32-H2");
    ESP_LOGI(TAG, "=========================================");

    /* --- 1. NVS --- */
    ESP_ERROR_CHECK(init_nvs());
    ESP_LOGI(TAG, "NVS flash initialised");

    /* --- 2. Event loop --- */
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    /* --- 3. IEEE 802.15.4 radio --- */
    ESP_ERROR_CHECK(init_ieee802154());

    /* --- 4. SPI bus (shared by display + SD card) --- */
    ESP_ERROR_CHECK(init_spi_bus());
    ESP_LOGI(TAG, "SPI bus initialised");

    /* --- 5. I2C bus (OLED display) --- */
    ESP_ERROR_CHECK(init_i2c_bus());
    ESP_LOGI(TAG, "I2C bus initialised");

    /* --- 6. SD card (non-fatal if absent) --- */
    esp_err_t sd_ret = init_sd_card();
    if (sd_ret != ESP_OK) {
        ESP_LOGW(TAG, "Continuing without SD card");
    }

    /* --- 7. Navigation buttons --- */
    ESP_ERROR_CHECK(init_buttons());
    ESP_LOGI(TAG, "Buttons initialised (UP=%d DOWN=%d SEL=%d BACK=%d)",
             PIN_BTN_UP, PIN_BTN_DOWN, PIN_BTN_SEL, PIN_BTN_BACK);

    /* --- 8. WS2812B status LED --- */
    ESP_ERROR_CHECK(init_led());
    ESP_LOGI(TAG, "WS2812B LED initialised");

    /* Brief green flash to signal successful boot */
    led_set_color(0, 64, 0);
    vTaskDelay(pdMS_TO_TICKS(300));
    led_set_color(0, 0, 0);

    /* --- 9. Launch FreeRTOS tasks --- */
    BaseType_t ret;

    ret = xTaskCreate(ui_task, "ui_task",
                      UI_TASK_STACK_SIZE, NULL, UI_TASK_PRIORITY, NULL);
    if (ret != pdPASS) {
        ESP_LOGE(TAG, "Failed to create ui_task");
    }

    ret = xTaskCreate(scanner_task, "scanner_task",
                      SCANNER_TASK_STACK_SIZE, NULL, SCANNER_TASK_PRIORITY, NULL);
    if (ret != pdPASS) {
        ESP_LOGE(TAG, "Failed to create scanner_task");
    }

    ret = xTaskCreate(sniffer_task, "sniffer_task",
                      SNIFFER_TASK_STACK_SIZE, NULL, SNIFFER_TASK_PRIORITY, NULL);
    if (ret != pdPASS) {
        ESP_LOGE(TAG, "Failed to create sniffer_task");
    }

    ESP_LOGI(TAG, "All subsystems initialised — ZigBlade ready");
}
