#ifndef ZIGBLADE_TEMBED_INPUT_H
#define ZIGBLADE_TEMBED_INPUT_H

#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    INPUT_EVENT_ROTATE_LEFT = 0,
    INPUT_EVENT_ROTATE_RIGHT,
    INPUT_EVENT_BUTTON_SHORT,
    INPUT_EVENT_BUTTON_LONG,
} input_event_type_t;

typedef struct {
    input_event_type_t type;
} input_event_t;

esp_err_t input_init(QueueHandle_t queue);

#ifdef __cplusplus
}
#endif

#endif
