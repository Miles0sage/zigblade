#ifndef ZIGBLADE_TEMBED_UI_H
#define ZIGBLADE_TEMBED_UI_H

#include "esp_err.h"
#include "uart_master.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t ui_tembed_init(void);
esp_err_t ui_tembed_render(const app_state_t *state);
esp_err_t ui_tembed_set_backlight(uint8_t brightness);

#ifdef __cplusplus
}
#endif

#endif
