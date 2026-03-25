#include "input.h"

#include "driver/gpio.h"
#include "esp_timer.h"
#include "freertos/task.h"

#define INPUT_ENCODER_A_GPIO      1
#define INPUT_ENCODER_B_GPIO      2
#define INPUT_BUTTON_GPIO         0
#define INPUT_POLL_MS             2
#define INPUT_LONG_PRESS_MS       700

typedef struct {
    QueueHandle_t queue;
    uint8_t prev_ab;
    bool button_prev;
    int64_t button_down_ms;
    bool long_sent;
} input_ctx_t;

static input_ctx_t s_input;

static void post_event(input_event_type_t type)
{
    input_event_t event = { .type = type };
    xQueueSend(s_input.queue, &event, 0);
}

static void input_task(void *arg)
{
    (void)arg;

    while (true) {
        uint8_t a = (uint8_t)gpio_get_level(INPUT_ENCODER_A_GPIO);
        uint8_t b = (uint8_t)gpio_get_level(INPUT_ENCODER_B_GPIO);
        uint8_t ab = (uint8_t)((a << 1) | b);
        uint8_t step = (uint8_t)((s_input.prev_ab << 2) | ab);

        switch (step) {
        case 0b0001:
        case 0b0111:
        case 0b1110:
        case 0b1000:
            post_event(INPUT_EVENT_ROTATE_RIGHT);
            break;
        case 0b0010:
        case 0b0100:
        case 0b1101:
        case 0b1011:
            post_event(INPUT_EVENT_ROTATE_LEFT);
            break;
        default:
            break;
        }
        s_input.prev_ab = ab;

        bool pressed = gpio_get_level(INPUT_BUTTON_GPIO) == 0;
        int64_t now_ms = esp_timer_get_time() / 1000;

        if (pressed && !s_input.button_prev) {
            s_input.button_down_ms = now_ms;
            s_input.long_sent = false;
        } else if (pressed && !s_input.long_sent &&
                   (now_ms - s_input.button_down_ms) >= INPUT_LONG_PRESS_MS) {
            post_event(INPUT_EVENT_BUTTON_LONG);
            s_input.long_sent = true;
        } else if (!pressed && s_input.button_prev && !s_input.long_sent) {
            post_event(INPUT_EVENT_BUTTON_SHORT);
        }
        s_input.button_prev = pressed;

        vTaskDelay(pdMS_TO_TICKS(INPUT_POLL_MS));
    }
}

esp_err_t input_init(QueueHandle_t queue)
{
    gpio_config_t cfg = {
        .pin_bit_mask = (1ULL << INPUT_ENCODER_A_GPIO) |
                        (1ULL << INPUT_ENCODER_B_GPIO) |
                        (1ULL << INPUT_BUTTON_GPIO),
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };

    s_input.queue = queue;
    ESP_ERROR_CHECK(gpio_config(&cfg));
    s_input.prev_ab = (uint8_t)((gpio_get_level(INPUT_ENCODER_A_GPIO) << 1) |
                                gpio_get_level(INPUT_ENCODER_B_GPIO));

    xTaskCreate(input_task, "input", 3072, NULL, 7, NULL);
    return ESP_OK;
}
