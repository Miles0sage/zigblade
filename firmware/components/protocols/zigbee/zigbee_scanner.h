/**
 * @file zigbee_scanner.h
 * @brief Zigbee network scanner — discovers active networks via beacon analysis.
 */

#ifndef ZIGBLADE_ZIGBEE_SCANNER_H
#define ZIGBLADE_ZIGBEE_SCANNER_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum number of networks the scanner can track simultaneously. */
#define ZIGBEE_SCAN_MAX_NETWORKS    32

/** Maximum devices tracked per network. */
#define ZIGBEE_SCAN_MAX_DEVICES     64

/** Per-channel dwell time during a full scan (milliseconds). */
#define ZIGBEE_SCAN_DWELL_MS        500

/** Security assessment for a discovered network */
typedef enum {
    ZB_ASSESS_UNKNOWN    = 0,           /**< Cannot determine             */
    ZB_ASSESS_VULNERABLE = 1,           /**< Weak security / open join    */
    ZB_ASSESS_HARDENED   = 2,           /**< Install codes / Zigbee 3.0   */
} zigbee_security_assessment_t;

/** Discovered Zigbee network descriptor */
typedef struct {
    uint16_t pan_id;                    /**< PAN identifier              */
    uint8_t  channel;                   /**< 802.15.4 channel (11-26)   */
    uint16_t coord_short_addr;          /**< Coordinator short address   */
    uint8_t  coord_ext_addr[8];         /**< Coordinator IEEE address    */
    bool     ext_addr_valid;            /**< coord_ext_addr is populated */
    uint8_t  stack_profile;             /**< Zigbee stack profile (1/2)  */
    uint8_t  zigbee_version;            /**< Zigbee protocol version     */
    bool     security_enabled;          /**< Network-level security on   */
    bool     permit_joining;            /**< Joining currently permitted */
    uint8_t  router_capacity;           /**< Router slots available      */
    uint8_t  end_device_capacity;       /**< End device slots available  */
    int8_t   rssi;                      /**< Strongest beacon RSSI       */
    uint8_t  device_count;              /**< Unique devices heard        */
    uint32_t last_seen_ms;              /**< Tick of last beacon/frame   */

    /* ── Zigbee 3.0 / install code detection (Weakness 4 fix) ──── */
    bool     is_zigbee_3_0;            /**< Zigbee 3.0 identified       */
    uint8_t  nwk_update_id;            /**< NWK update ID from beacon   */
    bool     install_code_required;    /**< Install code joining needed  */
    bool     centralized_tc;           /**< Centralized trust center    */
    bool     distributed_tc;           /**< Distributed trust center    */
    uint8_t  security_level;           /**< NWK security level (0-7)    */
    zigbee_security_assessment_t assessment; /**< Security assessment   */
} zigbee_network_t;

/** Scan result set */
typedef struct {
    zigbee_network_t networks[ZIGBEE_SCAN_MAX_NETWORKS];
    uint8_t          count;             /**< Number of discovered nets   */
    bool             scan_active;       /**< Scan currently running      */
    uint8_t          current_channel;   /**< Channel being scanned now   */
} zigbee_scan_result_t;

/**
 * @brief Start a full scan across all 16 channels (11-26).
 *
 * Iterates through each channel, dwelling for ZIGBEE_SCAN_DWELL_MS,
 * collecting beacon frames. Results accumulate in the internal list
 * and can be retrieved with zigbee_scan_get_results().
 *
 * This function is non-blocking — it spawns a FreeRTOS task.
 * Use zigbee_scan_get_results()->scan_active to check completion.
 *
 * @return ESP_OK on success.
 */
esp_err_t zigbee_scan_start(void);

/**
 * @brief Scan a single channel.
 *
 * Dwells on the given channel for ZIGBEE_SCAN_DWELL_MS, collecting
 * beacons and data frames. Non-blocking (spawns a task).
 *
 * @param channel  802.15.4 channel (11-26).
 * @return ESP_OK, or ESP_ERR_INVALID_ARG.
 */
esp_err_t zigbee_scan_channel(uint8_t channel);

/**
 * @brief Stop an in-progress scan.
 *
 * @return ESP_OK.
 */
esp_err_t zigbee_scan_stop(void);

/**
 * @brief Get a pointer to the current scan results.
 *
 * The returned pointer is valid until zigbee_scan_clear() is called.
 *
 * @return Pointer to scan results (never NULL).
 */
const zigbee_scan_result_t *zigbee_scan_get_results(void);

/**
 * @brief Clear all scan results.
 *
 * @return ESP_OK.
 */
esp_err_t zigbee_scan_clear(void);

/**
 * @brief Return a human-readable string for a security assessment.
 *
 * @param assessment  Assessment value.
 * @return Static string: "VULNERABLE", "HARDENED", or "UNKNOWN".
 */
const char *zigbee_assessment_str(zigbee_security_assessment_t assessment);

#ifdef __cplusplus
}
#endif

#endif /* ZIGBLADE_ZIGBEE_SCANNER_H */
