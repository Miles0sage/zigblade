#ifndef ZIGBLADE_TEMBED_WEB_UI_H
#define ZIGBLADE_TEMBED_WEB_UI_H

#include "esp_err.h"
#include "uart_master.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef esp_err_t (*web_ui_control_cb_t)(const char *action, const char *arg, void *ctx);

esp_err_t web_ui_start(app_state_t *state, web_ui_control_cb_t control_cb, void *control_ctx);
void web_ui_stop(void);
bool web_ui_is_running(void);

#ifdef __cplusplus
}
#endif

#endif
