/**
 * ZigBlade Screen Implementations
 *
 * All screen functions draw to the framebuffer and call display_update().
 */

#include "screens.h"
#include "display.h"
#include "font5x7.h"

#include <string.h>
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_mac.h"
#include "esp_chip_info.h"

/* ── Helpers ───────────────────────────────────────────────────────── */

/** Draw a horizontal divider line. */
static void draw_hline(int16_t y)
{
    display_line(0, y, DISPLAY_WIDTH - 1, y);
}

/** Centre a string horizontally at the given y position. */
static void draw_string_centered(int16_t y, const char *str)
{
    int16_t w = (int16_t)(strlen(str) * FONT_CELL_WIDTH);
    int16_t x = (DISPLAY_WIDTH - w) / 2;
    if (x < 0) x = 0;
    display_string(x, y, str);
}

/** Centre a 2x-scale string horizontally. */
static void draw_string_large_centered(int16_t y, const char *str)
{
    int16_t char_w = FONT_CHAR_WIDTH * 2 + 2;  /* 12 px per char at 2x */
    int16_t w = (int16_t)(strlen(str) * char_w);
    int16_t x = (DISPLAY_WIDTH - w) / 2;
    if (x < 0) x = 0;
    display_string_large(x, y, str);
}

/** Tiny itoa into a buffer, returns length written. */
static int itoa_simple(int32_t val, char *buf, size_t bufsz)
{
    if (bufsz == 0) return 0;
    char tmp[12];
    int ti = 0;
    bool neg = false;

    if (val < 0) { neg = true; val = -val; }
    if (val == 0) { tmp[ti++] = '0'; }
    while (val > 0 && ti < (int)sizeof(tmp)) {
        tmp[ti++] = '0' + (char)(val % 10);
        val /= 10;
    }

    int len = 0;
    if (neg && (size_t)(len + 1) < bufsz) buf[len++] = '-';
    for (int i = ti - 1; i >= 0 && (size_t)(len + 1) < bufsz; i--) {
        buf[len++] = tmp[i];
    }
    buf[len] = '\0';
    return len;
}

/* ── Splash screen ─────────────────────────────────────────────────── */

void screen_splash(void)
{
    display_clear();

    /* ZigBlade logo: draw a zigzag + blade shape */
    /* Zigzag */
    display_line(20, 8, 35, 18);
    display_line(35, 18, 20, 28);
    display_line(20, 28, 35, 38);
    /* Blade outline */
    display_line(40, 8,  108, 8);
    display_line(108, 8, 115, 23);
    display_line(115, 23, 108, 38);
    display_line(108, 38, 40, 38);
    display_line(40, 38, 40, 8);

    /* Title text */
    draw_string_large_centered(12, "ZigBlade");

    /* Divider */
    draw_hline(42);

    /* Version and subtitle */
    draw_string_centered(46, "Zigbee Pentest Tool");
    draw_string_centered(56, "v0.1.0");

    display_update();

    /* Hold splash for 2 seconds */
    vTaskDelay(pdMS_TO_TICKS(2000));
}

/* ── Scan progress screen ──────────────────────────────────────────── */

void screen_scan_progress(uint8_t channel, uint16_t found_count)
{
    display_clear();

    /* Header */
    display_rect(0, 0, DISPLAY_WIDTH, 10, true);
    /* Inverse "SCANNING" header */
    {
        const char *hdr = "SCANNING";
        int16_t hx = (DISPLAY_WIDTH - (int16_t)(strlen(hdr) * FONT_CELL_WIDTH)) / 2;
        for (const char *p = hdr; *p; p++) {
            char ch = *p;
            if (ch < FONT_FIRST_CHAR || ch > FONT_LAST_CHAR) ch = ' ';
            const uint8_t *glyph = font5x7[ch - FONT_FIRST_CHAR];
            for (int8_t col = 0; col < FONT_CHAR_WIDTH; col++) {
                uint8_t cd = glyph[col];
                for (int8_t row = 0; row < FONT_CHAR_HEIGHT; row++) {
                    if (cd & (1 << row)) {
                        display_pixel(hx + col, 2 + row, false);
                    }
                }
            }
            hx += FONT_CELL_WIDTH;
        }
    }

    /* Channel info */
    char buf[32];
    snprintf(buf, sizeof(buf), "Channel: %d / 26", channel);
    display_string(4, 16, buf);

    /* Networks found */
    snprintf(buf, sizeof(buf), "Found: %d networks", found_count);
    display_string(4, 28, buf);

    /* Progress bar — channels 11-26 mapped to 0-100% */
    uint8_t pct = 0;
    if (channel >= 11 && channel <= 26) {
        pct = (uint8_t)(((channel - 11) * 100) / 15);
    }
    display_progress_bar(4, 42, 120, 10, pct);

    /* Percent text */
    snprintf(buf, sizeof(buf), "%d%%", pct);
    draw_string_centered(54, buf);

    display_update();
}

/* ── Scan results screen ───────────────────────────────────────────── */

void screen_scan_results(const zigbee_network_t *networks, uint16_t count)
{
    display_clear();

    /* Header */
    char hdr[24];
    snprintf(hdr, sizeof(hdr), "Results (%d)", count);
    display_rect(0, 0, DISPLAY_WIDTH, 10, true);
    {
        int16_t hx = 2;
        for (const char *p = hdr; *p; p++) {
            char ch = *p;
            if (ch < FONT_FIRST_CHAR || ch > FONT_LAST_CHAR) ch = ' ';
            const uint8_t *glyph = font5x7[ch - FONT_FIRST_CHAR];
            for (int8_t col = 0; col < FONT_CHAR_WIDTH; col++) {
                uint8_t cd = glyph[col];
                for (int8_t row = 0; row < FONT_CHAR_HEIGHT; row++) {
                    if (cd & (1 << row)) {
                        display_pixel(hx + col, 2 + row, false);
                    }
                }
            }
            hx += FONT_CELL_WIDTH;
        }
    }

    /* Column headers */
    display_string(2,  12, "PAN");
    display_string(38, 12, "CH");
    display_string(58, 12, "RSSI");
    display_string(88, 12, "Addr");
    draw_hline(20);

    /* List entries (max 4 visible) */
    uint16_t max_show = (count < 4) ? count : 4;
    for (uint16_t i = 0; i < max_show; i++) {
        int16_t y = 22 + (int16_t)(i * 10);
        char line[8];

        /* PAN ID (hex) */
        snprintf(line, sizeof(line), "%04X", networks[i].pan_id);
        display_string(2, y, line);

        /* Channel */
        snprintf(line, sizeof(line), "%2d", networks[i].channel);
        display_string(38, y, line);

        /* RSSI */
        snprintf(line, sizeof(line), "%d", networks[i].rssi);
        display_string(58, y, line);

        /* Short address */
        snprintf(line, sizeof(line), "%04X", networks[i].short_addr);
        display_string(88, y, line);
    }

    if (count > 4) {
        char more[16];
        snprintf(more, sizeof(more), "+%d more", count - 4);
        draw_string_centered(56, more);
    }

    display_update();
}

/* ── Sniffer live view ─────────────────────────────────────────────── */

void screen_sniffer_live(uint32_t packet_count, const parsed_packet_t *last_pkt, uint8_t channel)
{
    display_clear();

    /* Header bar */
    display_rect(0, 0, DISPLAY_WIDTH, 10, true);
    {
        char hdr[24];
        snprintf(hdr, sizeof(hdr), "SNIFFER CH%d", channel);
        int16_t hx = 2;
        for (const char *p = hdr; *p; p++) {
            char ch = *p;
            if (ch < FONT_FIRST_CHAR || ch > FONT_LAST_CHAR) ch = ' ';
            const uint8_t *glyph = font5x7[ch - FONT_FIRST_CHAR];
            for (int8_t col = 0; col < FONT_CHAR_WIDTH; col++) {
                uint8_t cd = glyph[col];
                for (int8_t row = 0; row < FONT_CHAR_HEIGHT; row++) {
                    if (cd & (1 << row)) {
                        display_pixel(hx + col, 2 + row, false);
                    }
                }
            }
            hx += FONT_CELL_WIDTH;
        }
    }

    /* Packet counter */
    char buf[32];
    snprintf(buf, sizeof(buf), "Packets: %lu", (unsigned long)packet_count);
    display_string(4, 14, buf);

    draw_hline(23);

    /* Last packet info */
    if (last_pkt) {
        snprintf(buf, sizeof(buf), "#%lu %s", (unsigned long)last_pkt->seq,
                 last_pkt->type_str ? last_pkt->type_str : "???");
        display_string(4, 26, buf);

        snprintf(buf, sizeof(buf), "%04X->%04X len=%d",
                 last_pkt->src_addr, last_pkt->dst_addr, last_pkt->len);
        display_string(4, 36, buf);

        snprintf(buf, sizeof(buf), "RSSI:%d PAN:%04X",
                 last_pkt->rssi, last_pkt->pan_id);
        display_string(4, 46, buf);
    } else {
        draw_string_centered(34, "Waiting for packets...");
    }

    /* Bottom status: blinking capture indicator */
    static bool blink = false;
    blink = !blink;
    if (blink) {
        display_rect(2, 57, 4, 4, true);  /* small filled square = recording */
    }
    display_string(10, 56, "REC");

    display_update();
}

/* ── Packet detail screen ──────────────────────────────────────────── */

void screen_packet_detail(const parsed_packet_t *pkt)
{
    display_clear();

    if (!pkt) {
        draw_string_centered(28, "No packet data");
        display_update();
        return;
    }

    /* Header */
    char hdr[24];
    snprintf(hdr, sizeof(hdr), "PKT #%lu", (unsigned long)pkt->seq);
    display_rect(0, 0, DISPLAY_WIDTH, 10, true);
    {
        int16_t hx = 2;
        for (const char *p = hdr; *p; p++) {
            char ch = *p;
            if (ch < FONT_FIRST_CHAR || ch > FONT_LAST_CHAR) ch = ' ';
            const uint8_t *glyph = font5x7[ch - FONT_FIRST_CHAR];
            for (int8_t col = 0; col < FONT_CHAR_WIDTH; col++) {
                uint8_t cd = glyph[col];
                for (int8_t row = 0; row < FONT_CHAR_HEIGHT; row++) {
                    if (cd & (1 << row)) {
                        display_pixel(hx + col, 2 + row, false);
                    }
                }
            }
            hx += FONT_CELL_WIDTH;
        }
    }

    /* Fields */
    char buf[32];

    snprintf(buf, sizeof(buf), "Type: %s",
             pkt->type_str ? pkt->type_str : "Unknown");
    display_string(2, 13, buf);

    snprintf(buf, sizeof(buf), "Src:  %04X", pkt->src_addr);
    display_string(2, 22, buf);

    snprintf(buf, sizeof(buf), "Dst:  %04X", pkt->dst_addr);
    display_string(2, 31, buf);

    snprintf(buf, sizeof(buf), "PAN:  %04X  Len:%d", pkt->pan_id, pkt->len);
    display_string(2, 40, buf);

    snprintf(buf, sizeof(buf), "RSSI: %d dBm", pkt->rssi);
    display_string(2, 49, buf);

    /* First 8 payload bytes in hex */
    if (pkt->len > 0) {
        char hex[32];
        int pos = 0;
        uint8_t show = (pkt->len < 8) ? pkt->len : 8;
        for (uint8_t i = 0; i < show && pos < 28; i++) {
            pos += snprintf(&hex[pos], sizeof(hex) - (size_t)pos, "%02X ", pkt->payload[i]);
        }
        display_string(2, 56, hex);
    }

    display_update();
}

/* ── Attack status screen ──────────────────────────────────────────── */

void screen_attack_status(const char *attack_name, const char *status, uint8_t progress)
{
    display_clear();

    /* Header */
    display_rect(0, 0, DISPLAY_WIDTH, 10, true);
    {
        const char *hdr = "ATTACK";
        int16_t hx = (DISPLAY_WIDTH - (int16_t)(strlen(hdr) * FONT_CELL_WIDTH)) / 2;
        for (const char *p = hdr; *p; p++) {
            char ch = *p;
            if (ch < FONT_FIRST_CHAR || ch > FONT_LAST_CHAR) ch = ' ';
            const uint8_t *glyph = font5x7[ch - FONT_FIRST_CHAR];
            for (int8_t col = 0; col < FONT_CHAR_WIDTH; col++) {
                uint8_t cd = glyph[col];
                for (int8_t row = 0; row < FONT_CHAR_HEIGHT; row++) {
                    if (cd & (1 << row)) {
                        display_pixel(hx + col, 2 + row, false);
                    }
                }
            }
            hx += FONT_CELL_WIDTH;
        }
    }

    /* Attack name (large) */
    if (attack_name) {
        draw_string_centered(14, attack_name);
    }

    draw_hline(24);

    /* Status text */
    if (status) {
        draw_string_centered(28, status);
    }

    /* Progress bar */
    display_progress_bar(4, 40, 120, 10, progress);

    /* Percent text */
    char buf[8];
    snprintf(buf, sizeof(buf), "%d%%", progress);
    draw_string_centered(54, buf);

    display_update();
}

/* ── Settings screen ───────────────────────────────────────────────── */

void screen_settings(const settings_item_t *items, uint8_t count)
{
    display_clear();

    /* Header */
    display_rect(0, 0, DISPLAY_WIDTH, 10, true);
    {
        const char *hdr = "SETTINGS";
        int16_t hx = (DISPLAY_WIDTH - (int16_t)(strlen(hdr) * FONT_CELL_WIDTH)) / 2;
        for (const char *p = hdr; *p; p++) {
            char ch = *p;
            if (ch < FONT_FIRST_CHAR || ch > FONT_LAST_CHAR) ch = ' ';
            const uint8_t *glyph = font5x7[ch - FONT_FIRST_CHAR];
            for (int8_t col = 0; col < FONT_CHAR_WIDTH; col++) {
                uint8_t cd = glyph[col];
                for (int8_t row = 0; row < FONT_CHAR_HEIGHT; row++) {
                    if (cd & (1 << row)) {
                        display_pixel(hx + col, 2 + row, false);
                    }
                }
            }
            hx += FONT_CELL_WIDTH;
        }
    }

    /* Settings list */
    uint8_t max_show = (count < 5) ? count : 5;
    for (uint8_t i = 0; i < max_show; i++) {
        int16_t y = 13 + i * 10;

        display_string(2, y, items[i].name);

        /* Right-aligned value */
        char vbuf[16];
        if (items[i].is_toggle) {
            snprintf(vbuf, sizeof(vbuf), "%s", items[i].value ? "ON" : "OFF");
        } else if (items[i].unit) {
            snprintf(vbuf, sizeof(vbuf), "%ld%s", (long)items[i].value, items[i].unit);
        } else {
            snprintf(vbuf, sizeof(vbuf), "%ld", (long)items[i].value);
        }

        int16_t vx = DISPLAY_WIDTH - (int16_t)(strlen(vbuf) * FONT_CELL_WIDTH) - 2;
        display_string(vx, y, vbuf);
    }

    display_update();
}

/* ── About screen ──────────────────────────────────────────────────── */

void screen_about(void)
{
    display_clear();

    /* Title */
    draw_string_large_centered(0, "ZigBlade");
    draw_hline(16);

    display_string(2, 20, "Version: 0.1.0");
    display_string(2, 30, "Chip: ESP32-H2");

    /* MAC address */
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_IEEE802154);
    char mac_str[24];
    snprintf(mac_str, sizeof(mac_str), "MAC:%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    display_string(2, 40, mac_str);

    /* GitHub URL (truncated to fit) */
    display_string(2, 52, "github.com/zigblade");

    display_update();
}
