/**
 * ZigBlade Menu System
 *
 * Tree-structured menu with keyboard navigation.
 * Renders to the SH1106 framebuffer via display.h.
 */

#ifndef ZIGBLADE_MENU_H
#define ZIGBLADE_MENU_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Buttons ───────────────────────────────────────────────────────── */

#ifndef CONFIG_ZIGBLADE_BTN_UP_PIN
#define CONFIG_ZIGBLADE_BTN_UP_PIN      2
#endif
#ifndef CONFIG_ZIGBLADE_BTN_DOWN_PIN
#define CONFIG_ZIGBLADE_BTN_DOWN_PIN    3
#endif
#ifndef CONFIG_ZIGBLADE_BTN_SELECT_PIN
#define CONFIG_ZIGBLADE_BTN_SELECT_PIN  4
#endif
#ifndef CONFIG_ZIGBLADE_BTN_BACK_PIN
#define CONFIG_ZIGBLADE_BTN_BACK_PIN    5
#endif

#define BTN_DEBOUNCE_MS     50
#define BTN_LONG_PRESS_MS   500

typedef enum {
    BTN_UP = 0,
    BTN_DOWN,
    BTN_SELECT,
    BTN_BACK,
    BTN_COUNT
} button_id_t;

typedef enum {
    BTN_EVT_PRESS = 0,
    BTN_EVT_LONG_PRESS,
    BTN_EVT_RELEASE,
} button_event_type_t;

typedef struct {
    button_id_t         button;
    button_event_type_t type;
    int64_t             timestamp_ms;
} button_event_t;

/** Initialise button GPIOs with pull-ups and ISRs. */
esp_err_t button_init(void);

/**
 * Get the next button event (blocks up to timeout_ms).
 * Returns true if an event was received.
 */
bool button_get_event(button_event_t *evt, uint32_t timeout_ms);

/* ── Menu tree ─────────────────────────────────────────────────────── */

#define MENU_MAX_CHILDREN   8
#define MENU_MAX_DEPTH      4
#define MENU_NAME_LEN       20
#define MENU_VISIBLE_ITEMS  5   /* items visible on screen at once */

typedef enum {
    MENU_TYPE_SUBMENU = 0,  /* has children                        */
    MENU_TYPE_ACTION,       /* fires callback on SELECT            */
    MENU_TYPE_TOGGLE,       /* on/off value, toggled on SELECT     */
    MENU_TYPE_VALUE,        /* numeric value, +/- on UP/DOWN       */
} menu_item_type_t;

/** Forward declaration. */
typedef struct menu_item_s menu_item_t;

/** Callback fired when an ACTION item is selected or a TOGGLE/VALUE changes. */
typedef void (*menu_action_cb_t)(menu_item_t *item);

struct menu_item_s {
    char                name[MENU_NAME_LEN];
    char                icon;               /* single ASCII char shown left of name */
    menu_item_type_t    type;

    /* Children (SUBMENU only) */
    menu_item_t        *children[MENU_MAX_CHILDREN];
    uint8_t             child_count;

    /* Parent back-pointer (set by menu_init) */
    menu_item_t        *parent;

    /* Action callback */
    menu_action_cb_t    action;

    /* Value (TOGGLE: 0/1, VALUE: arbitrary) */
    int32_t             value;
    int32_t             value_min;
    int32_t             value_max;
};

/** Navigation state exposed to the renderer. */
typedef struct {
    menu_item_t *current;       /* currently displayed menu node (SUBMENU) */
    uint8_t      selected;      /* index of highlighted child              */
    uint8_t      scroll_offset; /* first visible child index               */
} menu_state_t;

/** Build the full menu tree and initialise navigation state. */
esp_err_t menu_init(void);

/** Process a button event and update navigation. */
void menu_handle_input(button_id_t btn, button_event_type_t type);

/** Get a read-only pointer to the current menu state. */
const menu_state_t *menu_get_current(void);

/** Render the current menu state to the display framebuffer and push. */
void menu_render(void);

/** Get the root menu item. */
menu_item_t *menu_get_root(void);

#ifdef __cplusplus
}
#endif

#endif /* ZIGBLADE_MENU_H */
