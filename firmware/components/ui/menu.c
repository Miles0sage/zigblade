/**
 * ZigBlade Menu System — Tree navigation + button handling
 */

#include "menu.h"
#include "display.h"

#include <string.h>
#include "esp_log.h"
#include "driver/gpio.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "esp_timer.h"

static const char *TAG = "menu";

/* ── Button handling ───────────────────────────────────────────────── */

static QueueHandle_t s_btn_queue = NULL;
static int64_t       s_last_press_time[BTN_COUNT] = {0};

static const gpio_num_t s_btn_pins[BTN_COUNT] = {
    CONFIG_ZIGBLADE_BTN_UP_PIN,
    CONFIG_ZIGBLADE_BTN_DOWN_PIN,
    CONFIG_ZIGBLADE_BTN_SELECT_PIN,
    CONFIG_ZIGBLADE_BTN_BACK_PIN,
};

static void IRAM_ATTR button_isr_handler(void *arg)
{
    uint32_t btn_id = (uint32_t)(uintptr_t)arg;
    int64_t now = esp_timer_get_time() / 1000;  /* ms */

    /* Debounce */
    if ((now - s_last_press_time[btn_id]) < BTN_DEBOUNCE_MS) return;
    s_last_press_time[btn_id] = now;

    button_event_t evt = {
        .button       = (button_id_t)btn_id,
        .type         = BTN_EVT_PRESS,
        .timestamp_ms = now,
    };

    BaseType_t xHigherPriorityTaskWoken = pdFALSE;
    xQueueSendFromISR(s_btn_queue, &evt, &xHigherPriorityTaskWoken);
    if (xHigherPriorityTaskWoken) portYIELD_FROM_ISR();
}

esp_err_t button_init(void)
{
    s_btn_queue = xQueueCreate(16, sizeof(button_event_t));
    if (!s_btn_queue) return ESP_ERR_NO_MEM;

    /* Install GPIO ISR service (shared across all pins) */
    esp_err_t ret = gpio_install_isr_service(0);
    if (ret != ESP_OK && ret != ESP_ERR_INVALID_STATE) {
        /* ESP_ERR_INVALID_STATE means already installed — that's fine */
        return ret;
    }

    for (int i = 0; i < BTN_COUNT; i++) {
        gpio_config_t io_conf = {
            .pin_bit_mask = (1ULL << s_btn_pins[i]),
            .mode         = GPIO_MODE_INPUT,
            .pull_up_en   = GPIO_PULLUP_ENABLE,
            .pull_down_en = GPIO_PULLDOWN_DISABLE,
            .intr_type    = GPIO_INTR_NEGEDGE,  /* active-low buttons */
        };
        ret = gpio_config(&io_conf);
        if (ret != ESP_OK) return ret;

        ret = gpio_isr_handler_add(s_btn_pins[i], button_isr_handler, (void *)(uintptr_t)i);
        if (ret != ESP_OK) return ret;
    }

    ESP_LOGI(TAG, "Buttons initialised (UP=%d DOWN=%d SEL=%d BACK=%d)",
             s_btn_pins[0], s_btn_pins[1], s_btn_pins[2], s_btn_pins[3]);
    return ESP_OK;
}

bool button_get_event(button_event_t *evt, uint32_t timeout_ms)
{
    if (!s_btn_queue || !evt) return false;

    button_event_t raw;
    if (xQueueReceive(s_btn_queue, &raw, pdMS_TO_TICKS(timeout_ms)) != pdTRUE) {
        return false;
    }

    /*
     * Long-press detection: after receiving a PRESS, wait briefly to see
     * if the button stays held.  Check GPIO level directly.
     */
    int64_t press_start = raw.timestamp_ms;
    bool is_long = false;

    /* Poll for long press threshold */
    int remaining_ms = (int)(BTN_LONG_PRESS_MS - BTN_DEBOUNCE_MS);
    if (remaining_ms > 0) {
        vTaskDelay(pdMS_TO_TICKS(remaining_ms));
        /* If pin is still low (held), it's a long press */
        if (gpio_get_level(s_btn_pins[raw.button]) == 0) {
            is_long = true;
        }
    }

    *evt = raw;
    if (is_long) {
        evt->type = BTN_EVT_LONG_PRESS;
    }
    (void)press_start;
    return true;
}

/* ── Menu tree — static allocation ─────────────────────────────────── */

/*
 * We statically allocate all menu nodes to avoid heap fragmentation
 * on a constrained MCU.  The tree is built in menu_init().
 */

/* Helper macro to define a submenu node */
#define MENU_SUBMENU(_var, _name, _icon) \
    static menu_item_t _var = { \
        .name = _name, .icon = _icon, .type = MENU_TYPE_SUBMENU, \
        .children = {0}, .child_count = 0, .parent = NULL, .action = NULL, \
        .value = 0, .value_min = 0, .value_max = 0 }

/* Helper macro to define an action node */
#define MENU_ACTION(_var, _name, _icon, _cb) \
    static menu_item_t _var = { \
        .name = _name, .icon = _icon, .type = MENU_TYPE_ACTION, \
        .children = {0}, .child_count = 0, .parent = NULL, .action = _cb, \
        .value = 0, .value_min = 0, .value_max = 0 }

/* Helper macro to define a toggle node */
#define MENU_TOGGLE(_var, _name, _icon, _cb, _val) \
    static menu_item_t _var = { \
        .name = _name, .icon = _icon, .type = MENU_TYPE_TOGGLE, \
        .children = {0}, .child_count = 0, .parent = NULL, .action = _cb, \
        .value = _val, .value_min = 0, .value_max = 1 }

/* Helper macro to define a value node */
#define MENU_VALUE(_var, _name, _icon, _cb, _val, _min, _max) \
    static menu_item_t _var = { \
        .name = _name, .icon = _icon, .type = MENU_TYPE_VALUE, \
        .children = {0}, .child_count = 0, .parent = NULL, .action = _cb, \
        .value = _val, .value_min = _min, .value_max = _max }

/* ── Stub callbacks (replaced by real implementation later) ──────── */

static void cb_stub(menu_item_t *item) {
    ESP_LOGI(TAG, "Action: %s", item->name);
}

/* ── Node declarations ─────────────────────────────────────────────── */

/* Root */
MENU_SUBMENU(s_root,         "ZigBlade v0.1",  '*');

/* Scan Networks */
MENU_SUBMENU(s_scan,         "Scan Networks",   'S');
MENU_ACTION (s_scan_full,    "Full Scan",       '>', cb_stub);
MENU_ACTION (s_scan_single,  "Single Channel",  '#', cb_stub);
MENU_ACTION (s_scan_results, "Scan Results",    '=', cb_stub);

/* Sniffer */
MENU_SUBMENU(s_sniff,        "Sniffer",         'N');
MENU_ACTION (s_sniff_start,  "Start Capture",   '>', cb_stub);
MENU_ACTION (s_sniff_chan,   "Set Channel",      '#', cb_stub);
MENU_ACTION (s_sniff_key,   "Set Key",           'K', cb_stub);
MENU_ACTION (s_sniff_view,  "View Packets",      '=', cb_stub);

/* Inject */
MENU_SUBMENU(s_inject,       "Inject",          'I');
MENU_ACTION (s_inj_replay,  "Replay Attack",    '>', cb_stub);
MENU_ACTION (s_inj_beacon,  "Beacon Flood",     '!', cb_stub);
MENU_ACTION (s_inj_disassoc,"Disassociate",     'X', cb_stub);
MENU_ACTION (s_inj_custom,  "Custom Frame",     '~', cb_stub);

/* Attacks */
MENU_SUBMENU(s_attacks,      "Attacks",         'A');
MENU_ACTION (s_atk_tl,      "Touchlink Steal",  'T', cb_stub);
MENU_ACTION (s_atk_key,     "Key Extract",       'K', cb_stub);
MENU_ACTION (s_atk_spoof,   "Coord. Spoof",     'C', cb_stub);
MENU_ACTION (s_atk_fuzz,    "ZCL Fuzz",          'F', cb_stub);

/* PCAP Files */
MENU_SUBMENU(s_pcap,         "PCAP Files",      'P');
MENU_ACTION (s_pcap_list,   "List Files",        '=', cb_stub);
MENU_ACTION (s_pcap_export, "Export via USB",    'U', cb_stub);
MENU_ACTION (s_pcap_delete, "Delete All",        'X', cb_stub);

/* Settings */
MENU_SUBMENU(s_settings,     "Settings",        'G');
MENU_VALUE  (s_set_txpwr,   "TX Power",          'P', cb_stub, 0, -20, 20);
MENU_VALUE  (s_set_bright,  "Brightness",        'B', cb_stub, 207, 0, 255);
MENU_TOGGLE (s_set_autosave,"Auto-save PCAP",    'A', cb_stub, 1);
MENU_ACTION (s_set_about,   "About",             '?', cb_stub);

/* ── Link helper ───────────────────────────────────────────────────── */

static void add_child(menu_item_t *parent, menu_item_t *child)
{
    if (parent->child_count >= MENU_MAX_CHILDREN) return;
    parent->children[parent->child_count++] = child;
    child->parent = parent;
}

/* ── Navigation state ──────────────────────────────────────────────── */

static menu_state_t s_state = { .current = NULL, .selected = 0, .scroll_offset = 0 };

/* ── Public API ────────────────────────────────────────────────────── */

esp_err_t menu_init(void)
{
    /* Build tree */
    add_child(&s_root, &s_scan);
    add_child(&s_root, &s_sniff);
    add_child(&s_root, &s_inject);
    add_child(&s_root, &s_attacks);
    add_child(&s_root, &s_pcap);
    add_child(&s_root, &s_settings);

    add_child(&s_scan, &s_scan_full);
    add_child(&s_scan, &s_scan_single);
    add_child(&s_scan, &s_scan_results);

    add_child(&s_sniff, &s_sniff_start);
    add_child(&s_sniff, &s_sniff_chan);
    add_child(&s_sniff, &s_sniff_key);
    add_child(&s_sniff, &s_sniff_view);

    add_child(&s_inject, &s_inj_replay);
    add_child(&s_inject, &s_inj_beacon);
    add_child(&s_inject, &s_inj_disassoc);
    add_child(&s_inject, &s_inj_custom);

    add_child(&s_attacks, &s_atk_tl);
    add_child(&s_attacks, &s_atk_key);
    add_child(&s_attacks, &s_atk_spoof);
    add_child(&s_attacks, &s_atk_fuzz);

    add_child(&s_pcap, &s_pcap_list);
    add_child(&s_pcap, &s_pcap_export);
    add_child(&s_pcap, &s_pcap_delete);

    add_child(&s_settings, &s_set_txpwr);
    add_child(&s_settings, &s_set_bright);
    add_child(&s_settings, &s_set_autosave);
    add_child(&s_settings, &s_set_about);

    /* Start at root */
    s_state.current       = &s_root;
    s_state.selected      = 0;
    s_state.scroll_offset = 0;

    ESP_LOGI(TAG, "Menu initialised (%d top-level items)", s_root.child_count);
    return ESP_OK;
}

void menu_handle_input(button_id_t btn, button_event_type_t type)
{
    menu_item_t *cur = s_state.current;
    if (!cur) return;

    switch (btn) {

    case BTN_UP:
        if (cur->type == MENU_TYPE_SUBMENU && cur->child_count > 0) {
            if (s_state.selected > 0) {
                s_state.selected--;
                if (s_state.selected < s_state.scroll_offset) {
                    s_state.scroll_offset = s_state.selected;
                }
            }
        }
        break;

    case BTN_DOWN:
        if (cur->type == MENU_TYPE_SUBMENU && cur->child_count > 0) {
            if (s_state.selected < cur->child_count - 1) {
                s_state.selected++;
                if (s_state.selected >= s_state.scroll_offset + MENU_VISIBLE_ITEMS) {
                    s_state.scroll_offset = s_state.selected - MENU_VISIBLE_ITEMS + 1;
                }
            }
        }
        break;

    case BTN_SELECT: {
        if (cur->type != MENU_TYPE_SUBMENU || cur->child_count == 0) break;
        menu_item_t *sel = cur->children[s_state.selected];
        if (!sel) break;

        switch (sel->type) {
        case MENU_TYPE_SUBMENU:
            /* Navigate into submenu */
            s_state.current       = sel;
            s_state.selected      = 0;
            s_state.scroll_offset = 0;
            break;

        case MENU_TYPE_ACTION:
            if (sel->action) sel->action(sel);
            break;

        case MENU_TYPE_TOGGLE:
            sel->value = sel->value ? 0 : 1;
            if (sel->action) sel->action(sel);
            break;

        case MENU_TYPE_VALUE:
            /* Short press: increment. Long press: execute action. */
            if (type == BTN_EVT_LONG_PRESS) {
                if (sel->action) sel->action(sel);
            } else {
                if (sel->value < sel->value_max) sel->value++;
                else sel->value = sel->value_min;  /* wrap */
            }
            break;
        }
        break;
    }

    case BTN_BACK:
        if (cur->parent) {
            /* Find our index in parent's children to restore selection */
            menu_item_t *parent = cur->parent;
            uint8_t idx = 0;
            for (uint8_t i = 0; i < parent->child_count; i++) {
                if (parent->children[i] == cur) { idx = i; break; }
            }
            s_state.current       = parent;
            s_state.selected      = idx;
            s_state.scroll_offset = (idx >= MENU_VISIBLE_ITEMS) ? idx - MENU_VISIBLE_ITEMS + 1 : 0;
        }
        break;

    default:
        break;
    }
}

const menu_state_t *menu_get_current(void)
{
    return &s_state;
}

menu_item_t *menu_get_root(void)
{
    return &s_root;
}

/* ── Rendering ─────────────────────────────────────────────────────── */

/**
 * Build a breadcrumb string from the current menu path.
 * e.g. "Attacks > ZCL Fuzz"
 */
static void build_breadcrumb(char *buf, size_t buflen)
{
    /* Walk up the tree to collect path segments */
    const menu_item_t *path[MENU_MAX_DEPTH];
    int depth = 0;
    const menu_item_t *node = s_state.current;
    while (node && depth < MENU_MAX_DEPTH) {
        path[depth++] = node;
        node = node->parent;
    }

    buf[0] = '\0';
    size_t pos = 0;
    for (int i = depth - 1; i >= 0; i--) {
        size_t nlen = strlen(path[i]->name);
        if (pos + nlen + 4 >= buflen) break;
        if (i < depth - 1) {
            buf[pos++] = ' ';
            buf[pos++] = '>';
            buf[pos++] = ' ';
        }
        memcpy(&buf[pos], path[i]->name, nlen);
        pos += nlen;
    }
    buf[pos] = '\0';
}

void menu_render(void)
{
    const menu_state_t *st = &s_state;
    if (!st->current) return;

    display_clear();

    /* ── Header: breadcrumb bar (inverse video) ───────────────────── */
    char crumb[64];
    build_breadcrumb(crumb, sizeof(crumb));

    /* Draw inverse header background */
    display_rect(0, 0, DISPLAY_WIDTH, 10, true);
    /* Draw breadcrumb text in "inverse" by clearing pixels */
    {
        int16_t cx = 2;
        for (const char *p = crumb; *p; p++) {
            if (cx + FONT_CHAR_WIDTH > DISPLAY_WIDTH - 2) break;
            char ch = *p;
            if (ch < FONT_FIRST_CHAR || ch > FONT_LAST_CHAR) ch = ' ';
            const uint8_t *glyph = font5x7[ch - FONT_FIRST_CHAR];
            for (int8_t col = 0; col < FONT_CHAR_WIDTH; col++) {
                uint8_t cd = glyph[col];
                for (int8_t row = 0; row < FONT_CHAR_HEIGHT; row++) {
                    if (cd & (1 << row)) {
                        display_pixel(cx + col, 2 + row, false);  /* clear = white on black bg */
                    }
                }
            }
            cx += FONT_CELL_WIDTH;
        }
    }

    /* ── Menu items ───────────────────────────────────────────────── */
    menu_item_t *cur = st->current;
    if (cur->type != MENU_TYPE_SUBMENU) {
        display_update();
        return;
    }

    int16_t y_start = 12;
    int16_t item_h  = 10;  /* pixels per menu row */

    for (uint8_t vi = 0; vi < MENU_VISIBLE_ITEMS && (st->scroll_offset + vi) < cur->child_count; vi++) {
        uint8_t idx = st->scroll_offset + vi;
        menu_item_t *item = cur->children[idx];
        if (!item) break;

        int16_t y = y_start + vi * item_h;
        bool selected = (idx == st->selected);

        /* Highlight bar for selected item */
        if (selected) {
            display_rect(0, y, DISPLAY_WIDTH, item_h, true);
        }

        /* Icon character */
        int16_t text_x = 2;
        if (selected) {
            /* Inverse text: clear pixels on filled background */
            char ic = item->icon;
            if (ic < FONT_FIRST_CHAR || ic > FONT_LAST_CHAR) ic = ' ';
            const uint8_t *glyph = font5x7[ic - FONT_FIRST_CHAR];
            for (int8_t col = 0; col < FONT_CHAR_WIDTH; col++) {
                uint8_t cd = glyph[col];
                for (int8_t row = 0; row < FONT_CHAR_HEIGHT; row++) {
                    if (cd & (1 << row)) {
                        display_pixel(text_x + col, y + 2 + row, false);
                    }
                }
            }
        } else {
            display_char(text_x, y + 2, item->icon);
        }
        text_x += FONT_CELL_WIDTH + 2;

        /* Item name */
        if (selected) {
            for (const char *p = item->name; *p; p++) {
                if (text_x + FONT_CHAR_WIDTH > DISPLAY_WIDTH - 2) break;
                char ch = *p;
                if (ch < FONT_FIRST_CHAR || ch > FONT_LAST_CHAR) ch = ' ';
                const uint8_t *glyph = font5x7[ch - FONT_FIRST_CHAR];
                for (int8_t col = 0; col < FONT_CHAR_WIDTH; col++) {
                    uint8_t cd = glyph[col];
                    for (int8_t row = 0; row < FONT_CHAR_HEIGHT; row++) {
                        if (cd & (1 << row)) {
                            display_pixel(text_x + col, y + 2 + row, false);
                        }
                    }
                }
                text_x += FONT_CELL_WIDTH;
            }
        } else {
            display_string(text_x, y + 2, item->name);
        }

        /* Right-aligned value indicator for TOGGLE / VALUE items */
        if (item->type == MENU_TYPE_TOGGLE) {
            const char *val_str = item->value ? "ON" : "OFF";
            int16_t vx = DISPLAY_WIDTH - (int16_t)(strlen(val_str) * FONT_CELL_WIDTH) - 2;
            if (selected) {
                for (const char *p = val_str; *p; p++) {
                    char ch = *p;
                    if (ch < FONT_FIRST_CHAR || ch > FONT_LAST_CHAR) ch = ' ';
                    const uint8_t *glyph = font5x7[ch - FONT_FIRST_CHAR];
                    for (int8_t col = 0; col < FONT_CHAR_WIDTH; col++) {
                        uint8_t cd = glyph[col];
                        for (int8_t row = 0; row < FONT_CHAR_HEIGHT; row++) {
                            if (cd & (1 << row)) {
                                display_pixel(vx + col, y + 2 + row, false);
                            }
                        }
                    }
                    vx += FONT_CELL_WIDTH;
                }
            } else {
                display_string(vx, y + 2, val_str);
            }
        } else if (item->type == MENU_TYPE_VALUE) {
            char vbuf[8];
            int len = 0;
            int32_t v = item->value;
            if (v < 0) { vbuf[len++] = '-'; v = -v; }
            /* simple itoa for small numbers */
            char tmp[8]; int ti = 0;
            if (v == 0) tmp[ti++] = '0';
            while (v > 0) { tmp[ti++] = '0' + (v % 10); v /= 10; }
            for (int i = ti - 1; i >= 0; i--) vbuf[len++] = tmp[i];
            vbuf[len] = '\0';

            int16_t vx = DISPLAY_WIDTH - (int16_t)(len * FONT_CELL_WIDTH) - 2;
            if (selected) {
                for (int ci = 0; ci < len; ci++) {
                    char ch = vbuf[ci];
                    if (ch < FONT_FIRST_CHAR || ch > FONT_LAST_CHAR) ch = ' ';
                    const uint8_t *glyph = font5x7[ch - FONT_FIRST_CHAR];
                    for (int8_t col = 0; col < FONT_CHAR_WIDTH; col++) {
                        uint8_t cd = glyph[col];
                        for (int8_t row = 0; row < FONT_CHAR_HEIGHT; row++) {
                            if (cd & (1 << row)) {
                                display_pixel(vx + col, y + 2 + row, false);
                            }
                        }
                    }
                    vx += FONT_CELL_WIDTH;
                }
            } else {
                display_string(vx, y + 2, vbuf);
            }
        } else if (item->type == MENU_TYPE_SUBMENU) {
            /* Show ">" indicator for submenus */
            int16_t ax = DISPLAY_WIDTH - FONT_CELL_WIDTH - 2;
            if (selected) {
                const uint8_t *glyph = font5x7['>' - FONT_FIRST_CHAR];
                for (int8_t col = 0; col < FONT_CHAR_WIDTH; col++) {
                    uint8_t cd = glyph[col];
                    for (int8_t row = 0; row < FONT_CHAR_HEIGHT; row++) {
                        if (cd & (1 << row)) {
                            display_pixel(ax + col, y + 2 + row, false);
                        }
                    }
                }
            } else {
                display_char(ax, y + 2, '>');
            }
        }
    }

    /* ── Scroll indicators ────────────────────────────────────────── */
    if (st->scroll_offset > 0) {
        /* Up arrow at top-right */
        display_pixel(DISPLAY_WIDTH - 3, y_start, true);
        display_pixel(DISPLAY_WIDTH - 4, y_start + 1, true);
        display_pixel(DISPLAY_WIDTH - 3, y_start + 1, true);
        display_pixel(DISPLAY_WIDTH - 2, y_start + 1, true);
    }
    if (st->scroll_offset + MENU_VISIBLE_ITEMS < cur->child_count) {
        /* Down arrow at bottom-right */
        int16_t ay = y_start + MENU_VISIBLE_ITEMS * 10 - 2;
        display_pixel(DISPLAY_WIDTH - 4, ay, true);
        display_pixel(DISPLAY_WIDTH - 3, ay, true);
        display_pixel(DISPLAY_WIDTH - 2, ay, true);
        display_pixel(DISPLAY_WIDTH - 3, ay + 1, true);
    }

    display_update();
}
