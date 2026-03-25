/**
 * ZigBlade Display Driver — SH1106 OLED 128x64 via I2C
 *
 * Raw I2C commands, no external library dependency.
 * Framebuffer in RAM, push to display with display_update().
 */

#ifndef ZIGBLADE_DISPLAY_H
#define ZIGBLADE_DISPLAY_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Hardware defaults (override via Kconfig) ──────────────────────── */

#ifndef CONFIG_ZIGBLADE_I2C_SDA_PIN
#define CONFIG_ZIGBLADE_I2C_SDA_PIN  1
#endif

#ifndef CONFIG_ZIGBLADE_I2C_SCL_PIN
#define CONFIG_ZIGBLADE_I2C_SCL_PIN  0
#endif

#ifndef CONFIG_ZIGBLADE_I2C_FREQ_HZ
#define CONFIG_ZIGBLADE_I2C_FREQ_HZ  400000
#endif

#define DISPLAY_WIDTH       128
#define DISPLAY_HEIGHT      64
#define DISPLAY_PAGES       (DISPLAY_HEIGHT / 8)
#define DISPLAY_BUF_SIZE    (DISPLAY_WIDTH * DISPLAY_PAGES)  /* 1024 bytes */

#define SH1106_I2C_ADDR     0x3C
#define SH1106_COL_OFFSET   2  /* SH1106 has 132-col RAM, display starts at col 2 */

/* ── API ───────────────────────────────────────────────────────────── */

/**
 * Initialise the I2C bus and SH1106 controller.
 * Must be called before any other display_*() function.
 */
esp_err_t display_init(void);

/** Clear the framebuffer (does NOT push to display). */
void display_clear(void);

/** Push the entire framebuffer to the OLED via I2C. */
esp_err_t display_update(void);

/** Set or clear a single pixel. */
void display_pixel(int16_t x, int16_t y, bool on);

/** Draw a single 5x7 character at pixel position (x, y). */
void display_char(int16_t x, int16_t y, char ch);

/** Draw a null-terminated string at pixel position (x, y). */
void display_string(int16_t x, int16_t y, const char *str);

/** Draw a null-terminated string at 2x scale (10x14 per char). */
void display_string_large(int16_t x, int16_t y, const char *str);

/** Draw a line between two points (Bresenham). */
void display_line(int16_t x0, int16_t y0, int16_t x1, int16_t y1);

/** Draw a rectangle (outline or filled). */
void display_rect(int16_t x, int16_t y, int16_t w, int16_t h, bool filled);

/** Draw a progress bar. percent: 0–100. */
void display_progress_bar(int16_t x, int16_t y, int16_t w, int16_t h, uint8_t percent);

/** Invert all display pixels (hardware command). */
esp_err_t display_invert(bool invert);

/** Set display contrast / brightness (0–255). */
esp_err_t display_set_brightness(uint8_t val);

/** Get a pointer to the raw framebuffer (read-only access). */
const uint8_t *display_get_framebuffer(void);

#ifdef __cplusplus
}
#endif

#endif /* ZIGBLADE_DISPLAY_H */
