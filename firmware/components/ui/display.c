/**
 * ZigBlade SH1106 OLED Display Driver — Raw I2C
 *
 * 128x64 monochrome OLED, I2C address 0x3C.
 * Uses ESP-IDF I2C master driver (legacy API for broad compatibility).
 */

#include "display.h"
#include "font5x7.h"

#include <string.h>
#include <stdlib.h>
#include "driver/i2c.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "display";

/* ── I2C plumbing ──────────────────────────────────────────────────── */

#define I2C_PORT        I2C_NUM_0
#define I2C_TIMEOUT_MS  100

/* SH1106 I2C protocol bytes */
#define SH1106_CMD_SINGLE   0x80  /* Co=1, D/C#=0  — single command byte follows */
#define SH1106_CMD_STREAM   0x00  /* Co=0, D/C#=0  — command stream follows      */
#define SH1106_DATA_STREAM  0x40  /* Co=0, D/C#=1  — data stream follows         */

/* ── Framebuffer ───────────────────────────────────────────────────── */

static uint8_t s_framebuf[DISPLAY_BUF_SIZE];
static bool    s_initialised = false;

/* ── Low-level I2C helpers ─────────────────────────────────────────── */

static esp_err_t sh1106_send_cmd(uint8_t cmd)
{
    i2c_cmd_handle_t handle = i2c_cmd_link_create();
    i2c_master_start(handle);
    i2c_master_write_byte(handle, (SH1106_I2C_ADDR << 1) | I2C_MASTER_WRITE, true);
    i2c_master_write_byte(handle, SH1106_CMD_SINGLE, true);
    i2c_master_write_byte(handle, cmd, true);
    i2c_master_stop(handle);
    esp_err_t ret = i2c_master_cmd_begin(I2C_PORT, handle, pdMS_TO_TICKS(I2C_TIMEOUT_MS));
    i2c_cmd_link_delete(handle);
    return ret;
}

static esp_err_t sh1106_send_cmd2(uint8_t cmd, uint8_t arg)
{
    i2c_cmd_handle_t handle = i2c_cmd_link_create();
    i2c_master_start(handle);
    i2c_master_write_byte(handle, (SH1106_I2C_ADDR << 1) | I2C_MASTER_WRITE, true);
    i2c_master_write_byte(handle, SH1106_CMD_STREAM, true);
    i2c_master_write_byte(handle, cmd, true);
    i2c_master_write_byte(handle, arg, true);
    i2c_master_stop(handle);
    esp_err_t ret = i2c_master_cmd_begin(I2C_PORT, handle, pdMS_TO_TICKS(I2C_TIMEOUT_MS));
    i2c_cmd_link_delete(handle);
    return ret;
}

static esp_err_t sh1106_send_data(const uint8_t *data, size_t len)
{
    i2c_cmd_handle_t handle = i2c_cmd_link_create();
    i2c_master_start(handle);
    i2c_master_write_byte(handle, (SH1106_I2C_ADDR << 1) | I2C_MASTER_WRITE, true);
    i2c_master_write_byte(handle, SH1106_DATA_STREAM, true);
    i2c_master_write(handle, data, len, true);
    i2c_master_stop(handle);
    esp_err_t ret = i2c_master_cmd_begin(I2C_PORT, handle, pdMS_TO_TICKS(I2C_TIMEOUT_MS));
    i2c_cmd_link_delete(handle);
    return ret;
}

/* ── Initialisation ────────────────────────────────────────────────── */

static esp_err_t i2c_bus_init(void)
{
    i2c_config_t conf = {
        .mode             = I2C_MODE_MASTER,
        .sda_io_num       = CONFIG_ZIGBLADE_I2C_SDA_PIN,
        .scl_io_num       = CONFIG_ZIGBLADE_I2C_SCL_PIN,
        .sda_pullup_en    = GPIO_PULLUP_ENABLE,
        .scl_pullup_en    = GPIO_PULLUP_ENABLE,
        .master.clk_speed = CONFIG_ZIGBLADE_I2C_FREQ_HZ,
    };
    esp_err_t ret = i2c_param_config(I2C_PORT, &conf);
    if (ret != ESP_OK) return ret;
    return i2c_driver_install(I2C_PORT, I2C_MODE_MASTER, 0, 0, 0);
}

esp_err_t display_init(void)
{
    esp_err_t ret;

    ret = i2c_bus_init();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "I2C bus init failed: %s", esp_err_to_name(ret));
        return ret;
    }

    /* Short delay for SH1106 power-up */
    vTaskDelay(pdMS_TO_TICKS(100));

    /*
     * SH1106 initialisation sequence.
     * Based on the SH1106 datasheet recommended settings for 128x64.
     */
    const uint8_t init_cmds[] = {
        0xAE,       /* Display OFF                                      */
        0xD5, 0x80, /* Set display clock div: default ratio             */
        0xA8, 0x3F, /* Set multiplex ratio: 64-1 = 0x3F                */
        0xD3, 0x00, /* Set display offset: 0                           */
        0x40,       /* Set start line: 0                                */
        0xAD, 0x8B, /* Set DC-DC: internal DC-DC enabled (8B)          */
        0xA1,       /* Set segment remap: column 127 = SEG0            */
        0xC8,       /* Set COM scan direction: remapped (C8 = reverse) */
        0xDA, 0x12, /* Set COM pins config: alternative, no remap      */
        0x81, 0xCF, /* Set contrast: 0xCF                              */
        0xD9, 0xF1, /* Set pre-charge period: phase1=1, phase2=15     */
        0xDB, 0x40, /* Set VCOMH deselect level: ~0.77×Vcc             */
        0xA4,       /* Entire display ON follows RAM content           */
        0xA6,       /* Set normal display (not inverted)               */
        0xAF,       /* Display ON                                      */
    };

    for (size_t i = 0; i < sizeof(init_cmds); i++) {
        /* Commands with a parameter byte: 0xD5, 0xA8, 0xD3, 0xAD, 0xDA, 0x81, 0xD9, 0xDB */
        ret = sh1106_send_cmd(init_cmds[i]);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "SH1106 init cmd 0x%02X failed: %s", init_cmds[i], esp_err_to_name(ret));
            return ret;
        }
    }

    memset(s_framebuf, 0x00, sizeof(s_framebuf));
    s_initialised = true;

    /* Push blank framebuffer to clear any residual GDDRAM content */
    return display_update();
}

/* ── Framebuffer operations ────────────────────────────────────────── */

void display_clear(void)
{
    memset(s_framebuf, 0x00, sizeof(s_framebuf));
}

esp_err_t display_update(void)
{
    if (!s_initialised) return ESP_ERR_INVALID_STATE;

    esp_err_t ret;
    for (uint8_t page = 0; page < DISPLAY_PAGES; page++) {
        /* Set page address */
        ret = sh1106_send_cmd(0xB0 | page);
        if (ret != ESP_OK) return ret;

        /* Set column address (SH1106 offset = 2) */
        uint8_t col = SH1106_COL_OFFSET;
        ret = sh1106_send_cmd(0x00 | (col & 0x0F));         /* lower nibble  */
        if (ret != ESP_OK) return ret;
        ret = sh1106_send_cmd(0x10 | ((col >> 4) & 0x0F));  /* upper nibble  */
        if (ret != ESP_OK) return ret;

        /* Send one page of pixel data (128 bytes) */
        ret = sh1106_send_data(&s_framebuf[page * DISPLAY_WIDTH], DISPLAY_WIDTH);
        if (ret != ESP_OK) return ret;
    }
    return ESP_OK;
}

void display_pixel(int16_t x, int16_t y, bool on)
{
    if (x < 0 || x >= DISPLAY_WIDTH || y < 0 || y >= DISPLAY_HEIGHT) return;
    uint16_t idx = (uint16_t)(x + (y / 8) * DISPLAY_WIDTH);
    uint8_t  bit = (uint8_t)(1 << (y & 7));
    if (on) {
        s_framebuf[idx] |= bit;
    } else {
        s_framebuf[idx] &= ~bit;
    }
}

/* ── Text rendering ────────────────────────────────────────────────── */

void display_char(int16_t x, int16_t y, char ch)
{
    if (ch < FONT_FIRST_CHAR || ch > FONT_LAST_CHAR) ch = ' ';
    const uint8_t *glyph = font5x7[ch - FONT_FIRST_CHAR];

    for (int8_t col = 0; col < FONT_CHAR_WIDTH; col++) {
        uint8_t column_data = glyph[col];
        for (int8_t row = 0; row < FONT_CHAR_HEIGHT; row++) {
            if (column_data & (1 << row)) {
                display_pixel(x + col, y + row, true);
            }
        }
    }
}

void display_string(int16_t x, int16_t y, const char *str)
{
    if (!str) return;
    int16_t cx = x;
    while (*str) {
        if (cx + FONT_CHAR_WIDTH > DISPLAY_WIDTH) break;
        display_char(cx, y, *str);
        cx += FONT_CELL_WIDTH;
        str++;
    }
}

void display_string_large(int16_t x, int16_t y, const char *str)
{
    if (!str) return;
    int16_t cx = x;
    while (*str) {
        char ch = *str;
        if (ch < FONT_FIRST_CHAR || ch > FONT_LAST_CHAR) ch = ' ';
        const uint8_t *glyph = font5x7[ch - FONT_FIRST_CHAR];

        for (int8_t col = 0; col < FONT_CHAR_WIDTH; col++) {
            uint8_t column_data = glyph[col];
            for (int8_t row = 0; row < FONT_CHAR_HEIGHT; row++) {
                if (column_data & (1 << row)) {
                    /* 2x scale: each source pixel becomes a 2x2 block */
                    int16_t px = cx + col * 2;
                    int16_t py = y + row * 2;
                    display_pixel(px,     py,     true);
                    display_pixel(px + 1, py,     true);
                    display_pixel(px,     py + 1, true);
                    display_pixel(px + 1, py + 1, true);
                }
            }
        }
        cx += FONT_CHAR_WIDTH * 2 + 2;  /* 10 + 2 gap = 12 px per char */
        str++;
    }
}

/* ── Geometry ──────────────────────────────────────────────────────── */

void display_line(int16_t x0, int16_t y0, int16_t x1, int16_t y1)
{
    /* Bresenham's line algorithm */
    int16_t dx = abs(x1 - x0);
    int16_t dy = -abs(y1 - y0);
    int16_t sx = (x0 < x1) ? 1 : -1;
    int16_t sy = (y0 < y1) ? 1 : -1;
    int16_t err = dx + dy;

    for (;;) {
        display_pixel(x0, y0, true);
        if (x0 == x1 && y0 == y1) break;
        int16_t e2 = 2 * err;
        if (e2 >= dy) { err += dy; x0 += sx; }
        if (e2 <= dx) { err += dx; y0 += sy; }
    }
}

void display_rect(int16_t x, int16_t y, int16_t w, int16_t h, bool filled)
{
    if (filled) {
        for (int16_t row = y; row < y + h; row++) {
            for (int16_t col = x; col < x + w; col++) {
                display_pixel(col, row, true);
            }
        }
    } else {
        display_line(x, y, x + w - 1, y);                 /* top    */
        display_line(x, y + h - 1, x + w - 1, y + h - 1); /* bottom */
        display_line(x, y, x, y + h - 1);                 /* left   */
        display_line(x + w - 1, y, x + w - 1, y + h - 1); /* right  */
    }
}

void display_progress_bar(int16_t x, int16_t y, int16_t w, int16_t h, uint8_t percent)
{
    if (percent > 100) percent = 100;

    /* Outer border */
    display_rect(x, y, w, h, false);

    /* Inner fill */
    int16_t fill_w = (int16_t)(((int32_t)(w - 4) * percent) / 100);
    if (fill_w > 0) {
        display_rect(x + 2, y + 2, fill_w, h - 4, true);
    }
}

/* ── Hardware commands ─────────────────────────────────────────────── */

esp_err_t display_invert(bool invert)
{
    return sh1106_send_cmd(invert ? 0xA7 : 0xA6);
}

esp_err_t display_set_brightness(uint8_t val)
{
    return sh1106_send_cmd2(0x81, val);
}

const uint8_t *display_get_framebuffer(void)
{
    return s_framebuf;
}
