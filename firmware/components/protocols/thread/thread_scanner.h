/**
 * @file thread_scanner.h
 * @brief Passive Thread network discovery from shared 802.15.4 captures.
 */

#ifndef ZIGBLADE_THREAD_SCANNER_H
#define ZIGBLADE_THREAD_SCANNER_H

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define THREAD_SCAN_MAX_NETWORKS 32

typedef struct {
    uint16_t pan_id;
    uint8_t  channel;
    uint16_t leader_short_addr;
    uint8_t  leader_ext_addr[8];
    bool     leader_ext_addr_valid;
    uint8_t  ext_pan_id[8];
    bool     ext_pan_id_valid;
    char     network_name[17];
    bool     network_name_valid;
    bool     mle_advertisement_seen;
    bool     commissioning_seen;
    int8_t   rssi;
    uint32_t last_seen_ms;
} thread_network_t;

typedef struct {
    thread_network_t networks[THREAD_SCAN_MAX_NETWORKS];
    uint8_t          count;
    bool             scan_active;
    uint8_t          current_channel;
    uint32_t         mle_advertisements;
} thread_scan_result_t;

esp_err_t thread_scan_start(void);
esp_err_t thread_scan_stop(void);
esp_err_t thread_scan_clear(void);
const thread_scan_result_t *thread_scan_get_results(void);
void thread_scan_process_packet(const uint8_t *frame,
                                uint8_t len,
                                int8_t rssi,
                                uint8_t channel,
                                uint32_t timestamp_us);

/* ── Active Thread attacks (Weakness 3 fix) ──────────────────────── */

/** Maximum DTLS passphrase length for commissioner brute-force */
#define THREAD_PASSPHRASE_MAX_LEN   32

/** Common Thread commissioner passphrases to try */
#define THREAD_PASSPHRASE_DICT_MAX  128

/** Result from a commissioner brute-force attempt */
typedef struct {
    bool     found;                   /**< true if passphrase was found   */
    char     passphrase[THREAD_PASSPHRASE_MAX_LEN + 1];
    uint32_t attempts;                /**< Number tried                   */
    uint32_t elapsed_ms;              /**< Wall time                      */
} thread_brute_result_t;

/** Extracted Thread network credentials */
typedef struct {
    bool     valid;                   /**< Extraction succeeded           */
    uint8_t  network_key[16];         /**< Thread Network Master Key      */
    bool     network_key_valid;
    uint8_t  pskc[16];               /**< Pre-Shared Key for Commissioner*/
    bool     pskc_valid;
    uint8_t  ext_pan_id[8];
    bool     ext_pan_id_valid;
    char     network_name[17];
    bool     network_name_valid;
    uint16_t pan_id;
    uint8_t  channel;
} thread_credentials_t;

/**
 * @brief Attempt DTLS passphrase brute-force against a Thread commissioner.
 *
 * Tries a dictionary of common Thread commissioner passphrases.
 * Thread commissioning uses DTLS with a PSK derived from the
 * passphrase + network name.  This function tries each candidate
 * passphrase against the captured DTLS ClientHello/ServerHello
 * handshake to find a match.
 *
 * @param[in]  dtls_handshake  Captured DTLS handshake bytes.
 * @param[in]  handshake_len   Handshake length.
 * @param[in]  network_name    Thread network name (for PSKc derivation).
 * @param[in]  ext_pan_id      8-byte Extended PAN ID.
 * @param[out] result          Output result.
 * @return ESP_OK if found, ESP_ERR_NOT_FOUND otherwise.
 */
esp_err_t thread_commissioner_brute(const uint8_t *dtls_handshake,
                                    uint8_t handshake_len,
                                    const char *network_name,
                                    const uint8_t *ext_pan_id,
                                    thread_brute_result_t *result);

/**
 * @brief Extract Thread network credentials from captured commissioning.
 *
 * Scans the captured MeshCoP dataset TLVs from commissioning traffic
 * to extract the Network Master Key, PSKc, and other credentials.
 *
 * @param[in]  meshcop_data  Captured MeshCoP dataset bytes.
 * @param[in]  data_len      Data length.
 * @param[out] creds         Output credentials structure.
 * @return ESP_OK if at least one credential was extracted.
 */
esp_err_t thread_credential_dump(const uint8_t *meshcop_data,
                                 uint8_t data_len,
                                 thread_credentials_t *creds);

#ifdef __cplusplus
}
#endif

#endif /* ZIGBLADE_THREAD_SCANNER_H */
