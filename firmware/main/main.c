/*
 * ZigBlade ESP32-H2 slave firmware entry point.
 *
 * The H2 owns the 802.15.4 radio and exposes a UART control plane to the
 * ESP32-S3 master. The master handles UI, Wi-Fi, and Sub-GHz peripherals.
 */

#include <stdio.h>

#include "esp_err.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "ieee802154_hal.h"
#include "zigbee_injector.h"
#include "uart_bridge.h"

static const char *TAG = "zigblade";

#define UART_BRIDGE_TASK_STACK_SIZE    (6 * 1024)
#define UART_BRIDGE_TASK_PRIORITY      6

static esp_err_t init_nvs(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    return ret;
}

void app_main(void)
{
    ESP_LOGI(TAG, "=========================================");
    ESP_LOGI(TAG, " ZigBlade ESP32-H2 Slave");
    ESP_LOGI(TAG, " Target: ESP32-H2");
    ESP_LOGI(TAG, "=========================================");

    ESP_ERROR_CHECK(init_nvs());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    ESP_ERROR_CHECK(zigblade_radio_init());
    ESP_ERROR_CHECK(zigbee_injector_init());
    ESP_ERROR_CHECK(uart_bridge_init(UART_BRIDGE_DEFAULT_UART,
                                     UART_BRIDGE_DEFAULT_TX_PIN,
                                     UART_BRIDGE_DEFAULT_RX_PIN,
                                     UART_BRIDGE_DEFAULT_BAUD));

    xTaskCreate(uart_bridge_task,
                "uart_bridge",
                UART_BRIDGE_TASK_STACK_SIZE,
                NULL,
                UART_BRIDGE_TASK_PRIORITY,
                NULL);
}
