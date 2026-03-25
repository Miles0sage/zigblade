/**
 * ZigBlade Screen Definitions
 *
 * Each screen function draws to the framebuffer via display.h
 * and calls display_update() to push to the OLED.
 */

#ifndef ZIGBLADE_SCREENS_H
#define ZIGBLADE_SCREENS_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Data types for screen content ─────────────────────────────────── */

/** Discovered Zigbee network info. */
typedef struct {
    uint16_t    pan_id;
    uint16_t    short_addr;
    uint8_t     channel;
    int8_t      rssi;
    char        label[16];      /* human-readable label or "Unknown" */
} zigbee_network_t;

/** Parsed packet summary for live view / detail view. */
typedef struct {
    uint32_t    seq;
    uint8_t     frame_type;     /* 0=beacon, 1=data, 2=ack, 3=cmd */
    uint16_t    src_addr;
    uint16_t    dst_addr;
    uint16_t    pan_id;
    int8_t      rssi;
    uint8_t     len;
    uint8_t     payload[128];
    const char *type_str;       /* "Beacon", "Data", "Ack", "Cmd" */
} parsed_packet_t;

/** Settings item for the settings screen. */
typedef struct {
    const char *name;
    int32_t     value;
    const char *unit;           /* "dBm", "%", NULL for on/off */
    bool        is_toggle;
} settings_item_t;

/* ── Screens ───────────────────────────────────────────────────────── */

/** Boot splash: ZigBlade logo + version. Blocks for ~2 seconds. */
void screen_splash(void);

/** Scanning progress: channel being scanned, networks found so far. */
void screen_scan_progress(uint8_t channel, uint16_t found_count);

/** List of discovered networks (scrollable). */
void screen_scan_results(const zigbee_network_t *networks, uint16_t count);

/** Live sniffer view: packet counter, last packet summary, channel. */
void screen_sniffer_live(uint32_t packet_count, const parsed_packet_t *last_pkt, uint8_t channel);

/** Detailed decoded packet fields. */
void screen_packet_detail(const parsed_packet_t *pkt);

/** Attack status: name, status string, progress 0–100. */
void screen_attack_status(const char *attack_name, const char *status, uint8_t progress);

/** Settings list with current values. */
void screen_settings(const settings_item_t *items, uint8_t count);

/** About / device info screen. */
void screen_about(void);

#ifdef __cplusplus
}
#endif

#endif /* ZIGBLADE_SCREENS_H */
