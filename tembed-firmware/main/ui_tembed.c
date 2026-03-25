#include "ui_tembed.h"

#include <stdio.h>
#include <string.h>

#include "driver/gpio.h"
#include "driver/spi_master.h"
#include "freertos/task.h"

#define TFT_HOST                 SPI2_HOST
#define TFT_WIDTH                320
#define TFT_HEIGHT               170
#define TFT_X_OFFSET             0
#define TFT_Y_OFFSET             35

#define TFT_PIN_SCLK             12
#define TFT_PIN_MOSI             11
#define TFT_PIN_CS               10
#define TFT_PIN_DC               13
#define TFT_PIN_RST              9
#define TFT_PIN_BL               46

#define RGB565(r, g, b) (uint16_t)((((r) & 0xF8U) << 8) | (((g) & 0xFCU) << 3) | (((b) & 0xF8U) >> 3))

static spi_device_handle_t s_lcd;

static const char *k_menu_labels[MENU_COUNT] = {
    "SCAN",
    "SNIFFER",
    "ATTACKS",
    "SUBGHZ",
    "WIFI",
    "SETTINGS",
    "WEB UI",
};

static const uint16_t C_BG = RGB565(6, 10, 18);
static const uint16_t C_PANEL = RGB565(16, 24, 40);
static const uint16_t C_TEXT = RGB565(235, 241, 255);
static const uint16_t C_MUTED = RGB565(120, 132, 150);
static const uint16_t C_ACCENT = RGB565(0, 198, 255);
static const uint16_t C_WARN = RGB565(255, 96, 96);
static const uint16_t C_OK = RGB565(74, 214, 110);
static const uint16_t C_GOLD = RGB565(250, 198, 76);

static const uint8_t *glyph_for_char(char c)
{
    static const uint8_t glyphs[][5] = {
        [0]  = {0x00, 0x00, 0x00, 0x00, 0x00},
        [1]  = {0x0E, 0x11, 0x1F, 0x11, 0x11},
        [2]  = {0x1E, 0x11, 0x1E, 0x11, 0x1E},
        [3]  = {0x0F, 0x10, 0x10, 0x10, 0x0F},
        [4]  = {0x1E, 0x11, 0x11, 0x11, 0x1E},
        [5]  = {0x1F, 0x10, 0x1E, 0x10, 0x1F},
        [6]  = {0x1F, 0x10, 0x1E, 0x10, 0x10},
        [7]  = {0x0F, 0x10, 0x17, 0x11, 0x0F},
        [8]  = {0x11, 0x11, 0x1F, 0x11, 0x11},
        [9]  = {0x1F, 0x04, 0x04, 0x04, 0x1F},
        [10] = {0x07, 0x02, 0x02, 0x12, 0x0C},
        [11] = {0x11, 0x12, 0x1C, 0x12, 0x11},
        [12] = {0x10, 0x10, 0x10, 0x10, 0x1F},
        [13] = {0x11, 0x1B, 0x15, 0x11, 0x11},
        [14] = {0x11, 0x19, 0x15, 0x13, 0x11},
        [15] = {0x0E, 0x11, 0x11, 0x11, 0x0E},
        [16] = {0x1E, 0x11, 0x1E, 0x10, 0x10},
        [17] = {0x0E, 0x11, 0x11, 0x15, 0x0E},
        [18] = {0x1E, 0x11, 0x1E, 0x12, 0x11},
        [19] = {0x0F, 0x10, 0x0E, 0x01, 0x1E},
        [20] = {0x1F, 0x04, 0x04, 0x04, 0x04},
        [21] = {0x11, 0x11, 0x11, 0x11, 0x0E},
        [22] = {0x11, 0x11, 0x11, 0x0A, 0x04},
        [23] = {0x11, 0x11, 0x15, 0x1B, 0x11},
        [24] = {0x11, 0x0A, 0x04, 0x0A, 0x11},
        [25] = {0x11, 0x0A, 0x04, 0x04, 0x04},
        [26] = {0x1F, 0x02, 0x04, 0x08, 0x1F},
        [27] = {0x0E, 0x11, 0x11, 0x11, 0x0E},
        [28] = {0x04, 0x0C, 0x04, 0x04, 0x0E},
        [29] = {0x0E, 0x11, 0x02, 0x04, 0x1F},
        [30] = {0x1E, 0x01, 0x06, 0x01, 0x1E},
        [31] = {0x12, 0x12, 0x1F, 0x02, 0x02},
        [32] = {0x1F, 0x10, 0x1E, 0x01, 0x1E},
        [33] = {0x07, 0x08, 0x1E, 0x11, 0x0E},
        [34] = {0x1F, 0x01, 0x02, 0x04, 0x04},
        [35] = {0x0E, 0x11, 0x0E, 0x11, 0x0E},
        [36] = {0x0E, 0x11, 0x0F, 0x01, 0x0E},
        [37] = {0x00, 0x04, 0x00, 0x04, 0x00},
        [38] = {0x00, 0x00, 0x1F, 0x00, 0x00},
        [39] = {0x00, 0x00, 0x00, 0x06, 0x06},
        [40] = {0x01, 0x02, 0x04, 0x08, 0x10},
        [41] = {0x00, 0x0E, 0x00, 0x0E, 0x00},
    };

    if (c >= 'A' && c <= 'Z') {
        return glyphs[c - 'A' + 1];
    }
    if (c >= '0' && c <= '9') {
        return glyphs[c - '0' + 27];
    }
    switch (c) {
    case ' ': return glyphs[0];
    case ':': return glyphs[37];
    case '-': return glyphs[38];
    case '.': return glyphs[39];
    case '/': return glyphs[40];
    case '=': return glyphs[41];
    default:  return glyphs[0];
    }
}

static void lcd_tx(bool is_data, const void *data, size_t len)
{
    gpio_set_level(TFT_PIN_DC, is_data ? 1 : 0);
    spi_transaction_t t = {
        .length = len * 8,
        .tx_buffer = data,
    };
    ESP_ERROR_CHECK(spi_device_polling_transmit(s_lcd, &t));
}

static void lcd_cmd(uint8_t cmd)
{
    lcd_tx(false, &cmd, 1);
}

static void lcd_data(const void *data, size_t len)
{
    lcd_tx(true, data, len);
}

static void lcd_set_addr_window(uint16_t x0, uint16_t y0, uint16_t x1, uint16_t y1)
{
    uint8_t buf[4];

    lcd_cmd(0x2A);
    buf[0] = (uint8_t)((x0 + TFT_X_OFFSET) >> 8);
    buf[1] = (uint8_t)(x0 + TFT_X_OFFSET);
    buf[2] = (uint8_t)((x1 + TFT_X_OFFSET) >> 8);
    buf[3] = (uint8_t)(x1 + TFT_X_OFFSET);
    lcd_data(buf, sizeof(buf));

    lcd_cmd(0x2B);
    buf[0] = (uint8_t)((y0 + TFT_Y_OFFSET) >> 8);
    buf[1] = (uint8_t)(y0 + TFT_Y_OFFSET);
    buf[2] = (uint8_t)((y1 + TFT_Y_OFFSET) >> 8);
    buf[3] = (uint8_t)(y1 + TFT_Y_OFFSET);
    lcd_data(buf, sizeof(buf));

    lcd_cmd(0x2C);
}

static void lcd_fill_rect(int x, int y, int w, int h, uint16_t color)
{
    if (w <= 0 || h <= 0) {
        return;
    }
    if (x < 0) {
        w += x;
        x = 0;
    }
    if (y < 0) {
        h += y;
        y = 0;
    }
    if (x + w > TFT_WIDTH) {
        w = TFT_WIDTH - x;
    }
    if (y + h > TFT_HEIGHT) {
        h = TFT_HEIGHT - y;
    }
    if (w <= 0 || h <= 0) {
        return;
    }

    lcd_set_addr_window((uint16_t)x, (uint16_t)y, (uint16_t)(x + w - 1), (uint16_t)(y + h - 1));
    uint16_t line[80];
    for (size_t i = 0; i < sizeof(line) / sizeof(line[0]); i++) {
        line[i] = (uint16_t)((color << 8) | (color >> 8));
    }
    int remaining = w * h;
    while (remaining > 0) {
        int chunk = remaining;
        if (chunk > (int)(sizeof(line) / sizeof(line[0]))) {
            chunk = (int)(sizeof(line) / sizeof(line[0]));
        }
        lcd_data(line, (size_t)chunk * sizeof(uint16_t));
        remaining -= chunk;
    }
}

static void lcd_draw_pixel(int x, int y, uint16_t color)
{
    uint16_t swapped = (uint16_t)((color << 8) | (color >> 8));
    lcd_set_addr_window((uint16_t)x, (uint16_t)y, (uint16_t)x, (uint16_t)y);
    lcd_data(&swapped, sizeof(swapped));
}

static void lcd_draw_text(int x, int y, const char *text, uint16_t color, uint16_t bg, int scale)
{
    while (*text != '\0') {
        const uint8_t *glyph = glyph_for_char(*text);
        for (int col = 0; col < 5; col++) {
            for (int row = 0; row < 5; row++) {
                uint16_t px = (glyph[col] & (1U << row)) ? color : bg;
                if (bg == 0xFFFF && !(glyph[col] & (1U << row))) {
                    continue;
                }
                lcd_fill_rect(x + col * scale, y + row * scale, scale, scale, px);
            }
        }
        x += 6 * scale;
        text++;
    }
}

static void lcd_draw_frame(int x, int y, int w, int h, uint16_t color)
{
    lcd_fill_rect(x, y, w, 2, color);
    lcd_fill_rect(x, y + h - 2, w, 2, color);
    lcd_fill_rect(x, y, 2, h, color);
    lcd_fill_rect(x + w - 2, y, 2, h, color);
}

static void lcd_draw_status_bar(const app_state_t *state)
{
    char right[32];
    lcd_fill_rect(0, 0, TFT_WIDTH, 24, C_PANEL);
    lcd_draw_text(10, 7, "ZIGBLADE", C_TEXT, C_PANEL, 2);
    snprintf(right, sizeof(right), "CH %02u", state->current_channel);
    lcd_draw_text(248, 7, right, C_ACCENT, C_PANEL, 2);
}

static void render_splash(void)
{
    lcd_fill_rect(0, 0, TFT_WIDTH, TFT_HEIGHT, C_BG);
    lcd_fill_rect(28, 18, 264, 6, C_ACCENT);
    lcd_fill_rect(28, 144, 264, 6, C_ACCENT);
    lcd_draw_text(70, 48, "ZIG", C_TEXT, C_BG, 5);
    lcd_draw_text(78, 100, "BLADE", C_WARN, C_BG, 3);
    lcd_draw_text(68, 134, "T-EMBED COMPANION", C_MUTED, C_BG, 1);
}

static void render_menu(const app_state_t *state)
{
    lcd_fill_rect(0, 24, TFT_WIDTH, TFT_HEIGHT - 24, C_BG);
    for (int i = 0; i < MENU_COUNT; i++) {
        int y = 34 + i * 18;
        bool selected = (uint8_t)i == state->menu_index;
        lcd_fill_rect(18, y, TFT_WIDTH - 36, 14, selected ? C_ACCENT : C_PANEL);
        lcd_draw_text(28, y + 2, k_menu_labels[i], selected ? C_BG : C_TEXT, selected ? C_ACCENT : C_PANEL, 2);
    }
    lcd_draw_text(22, 154, "ROTATE NAVIGATE  PRESS SELECT  HOLD BACK", C_MUTED, C_BG, 1);
}

static void render_scan(const app_state_t *state)
{
    char line[48];
    lcd_fill_rect(0, 24, TFT_WIDTH, TFT_HEIGHT - 24, C_BG);
    lcd_draw_text(18, 34, "ZIGBEE SCAN", C_TEXT, C_BG, 2);
    snprintf(line, sizeof(line), "NETWORKS %u", (unsigned)state->network_count);
    lcd_draw_text(18, 56, line, C_ACCENT, C_BG, 2);
    for (size_t i = 0; i < state->network_count && i < 5; i++) {
        snprintf(line, sizeof(line), "%04X CH%02u %dDBM",
                 state->networks[i].pan_id,
                 state->networks[i].channel,
                 state->networks[i].rssi);
        lcd_fill_rect(18, 78 + (int)i * 16, 284, 12, C_PANEL);
        lcd_draw_text(24, 80 + (int)i * 16, line, C_TEXT, C_PANEL, 1);
    }
}

static void render_sniffer(const app_state_t *state)
{
    char line[56];
    lcd_fill_rect(0, 24, TFT_WIDTH, TFT_HEIGHT - 24, C_BG);
    lcd_draw_text(18, 34, "LIVE SNIFFER", C_TEXT, C_BG, 2);
    snprintf(line, sizeof(line), "PACKETS %lu", (unsigned long)state->total_packets);
    lcd_draw_text(18, 56, line, C_OK, C_BG, 2);
    for (size_t i = 0; i < state->packet_count && i < 5; i++) {
        size_t idx = (state->packet_head + APP_MAX_PACKET_LOG - 1 - i) % APP_MAX_PACKET_LOG;
        const zb_packet_info_t *pkt = &state->packets[idx];
        snprintf(line, sizeof(line), "CH%02u RSSI %d LEN %u",
                 pkt->channel,
                 pkt->rssi,
                 (unsigned)pkt->len);
        lcd_fill_rect(18, 78 + (int)i * 16, 284, 12, C_PANEL);
        lcd_draw_text(24, 80 + (int)i * 16, line, C_TEXT, C_PANEL, 1);
    }
}

static void render_attack_screen(void)
{
    lcd_fill_rect(0, 24, TFT_WIDTH, TFT_HEIGHT - 24, C_BG);
    lcd_draw_text(18, 34, "ATTACK LAUNCHER", C_TEXT, C_BG, 2);
    lcd_draw_text(18, 66, "SAFE BUILD", C_WARN, C_BG, 3);
    lcd_draw_text(18, 108, "OFFENSIVE ACTIONS DISABLED", C_MUTED, C_BG, 1);
    lcd_draw_text(18, 122, "UART ATTACK COMMANDS ARE REJECTED", C_MUTED, C_BG, 1);
}

static void render_subghz(void)
{
    lcd_fill_rect(0, 24, TFT_WIDTH, TFT_HEIGHT - 24, C_BG);
    lcd_draw_text(18, 34, "SUBGHZ TOOLS", C_TEXT, C_BG, 2);
    lcd_draw_text(18, 66, "CC1101 LINK READY", C_GOLD, C_BG, 2);
    lcd_draw_text(18, 94, "REGISTER/RX WORKFLOWS CAN BE ADDED HERE", C_MUTED, C_BG, 1);
}

static void render_wifi(const app_state_t *state)
{
    lcd_fill_rect(0, 24, TFT_WIDTH, TFT_HEIGHT - 24, C_BG);
    lcd_draw_text(18, 34, "WIFI TOOLS", C_TEXT, C_BG, 2);
    lcd_draw_text(18, 56, "PASSIVE SCAN ENABLED", C_OK, C_BG, 2);
    lcd_draw_text(18, 76, "DEAUTH DISABLED IN SAFE BUILD", C_WARN, C_BG, 1);
    for (uint8_t i = 0; i < state->wifi_network_count && i < 5; i++) {
        lcd_fill_rect(18, 94 + i * 14, 284, 10, C_PANEL);
        lcd_draw_text(24, 96 + i * 14, state->wifi_networks[i], C_TEXT, C_PANEL, 1);
    }
}

static void render_settings(const app_state_t *state)
{
    char line[48];
    lcd_fill_rect(0, 24, TFT_WIDTH, TFT_HEIGHT - 24, C_BG);
    lcd_draw_text(18, 34, "SETTINGS", C_TEXT, C_BG, 2);
    snprintf(line, sizeof(line), "CHANNEL %u", state->current_channel);
    lcd_draw_text(18, 66, line, C_TEXT, C_BG, 2);
    snprintf(line, sizeof(line), "TX POWER %d DBM", state->tx_power_dbm);
    lcd_draw_text(18, 90, line, C_TEXT, C_BG, 2);
    snprintf(line, sizeof(line), "BRIGHTNESS %u", state->brightness);
    lcd_draw_text(18, 114, line, C_TEXT, C_BG, 2);
    lcd_draw_text(18, 144, "ROTATE TO CHANGE BRIGHTNESS HERE", C_MUTED, C_BG, 1);
}

static void render_web(const app_state_t *state)
{
    lcd_fill_rect(0, 24, TFT_WIDTH, TFT_HEIGHT - 24, C_BG);
    lcd_draw_text(18, 34, "WEB DASHBOARD", C_TEXT, C_BG, 2);
    lcd_draw_text(18, 64, state->web_ui_active ? "AP ACTIVE 192.168.4.1" : "STARTING AP", C_ACCENT, C_BG, 2);
    lcd_draw_text(18, 94, "SSID ZIGBLADE-TEMBED", C_TEXT, C_BG, 1);
    lcd_draw_text(18, 112, "PASSWORD zigblade123", C_TEXT, C_BG, 1);
}

esp_err_t ui_tembed_set_backlight(uint8_t brightness)
{
    return gpio_set_level(TFT_PIN_BL, brightness > 0 ? 1 : 0);
}

esp_err_t ui_tembed_init(void)
{
    spi_bus_config_t buscfg = {
        .mosi_io_num = TFT_PIN_MOSI,
        .miso_io_num = -1,
        .sclk_io_num = TFT_PIN_SCLK,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = TFT_WIDTH * 40 * 2,
    };
    spi_device_interface_config_t devcfg = {
        .clock_speed_hz = 40 * 1000 * 1000,
        .mode = 0,
        .spics_io_num = TFT_PIN_CS,
        .queue_size = 4,
    };
    gpio_config_t outcfg = {
        .pin_bit_mask = (1ULL << TFT_PIN_DC) | (1ULL << TFT_PIN_RST) | (1ULL << TFT_PIN_BL),
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };

    ESP_ERROR_CHECK(gpio_config(&outcfg));
    ESP_ERROR_CHECK(spi_bus_initialize(TFT_HOST, &buscfg, SPI_DMA_CH_AUTO));
    ESP_ERROR_CHECK(spi_bus_add_device(TFT_HOST, &devcfg, &s_lcd));

    gpio_set_level(TFT_PIN_RST, 0);
    vTaskDelay(pdMS_TO_TICKS(20));
    gpio_set_level(TFT_PIN_RST, 1);
    vTaskDelay(pdMS_TO_TICKS(120));

    lcd_cmd(0x01);
    vTaskDelay(pdMS_TO_TICKS(120));
    lcd_cmd(0x11);
    vTaskDelay(pdMS_TO_TICKS(120));
    {
        const uint8_t madctl = 0x70;
        const uint8_t colmod = 0x55;
        lcd_cmd(0x36);
        lcd_data(&madctl, 1);
        lcd_cmd(0x3A);
        lcd_data(&colmod, 1);
        lcd_cmd(0x21);
        lcd_cmd(0x29);
    }

    ui_tembed_set_backlight(255);
    render_splash();
    return ESP_OK;
}

esp_err_t ui_tembed_render(const app_state_t *state)
{
    lcd_draw_status_bar(state);
    switch (state->screen) {
    case APP_SCREEN_SPLASH:
        render_splash();
        break;
    case APP_SCREEN_MENU:
        render_menu(state);
        break;
    case APP_SCREEN_SCAN:
        render_scan(state);
        break;
    case APP_SCREEN_SNIFFER:
        render_sniffer(state);
        break;
    case APP_SCREEN_ATTACKS:
        render_attack_screen();
        break;
    case APP_SCREEN_SUBGHZ:
        render_subghz();
        break;
    case APP_SCREEN_WIFI:
        render_wifi(state);
        break;
    case APP_SCREEN_SETTINGS:
        render_settings(state);
        break;
    case APP_SCREEN_WEB_UI:
        render_web(state);
        break;
    default:
        break;
    }
    if (state->status_line[0] != '\0') {
        lcd_fill_rect(0, TFT_HEIGHT - 16, TFT_WIDTH, 16, C_PANEL);
        lcd_draw_text(10, TFT_HEIGHT - 12, state->status_line, C_MUTED, C_PANEL, 1);
        lcd_draw_frame(0, TFT_HEIGHT - 16, TFT_WIDTH, 16, C_PANEL);
    }
    return ESP_OK;
}
