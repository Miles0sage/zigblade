/**
 * @file zigbee_install_code.h
 * @brief Zigbee 3.0 install code attack module.
 *
 * Modern Zigbee 3.0 devices use unique per-device install codes instead
 * of the default ZigBeeAlliance09 trust center link key.  This module
 * provides:
 *   - Detection of install-code-protected vs default-key networks
 *   - CRC-based install code validation (MMO hash → link key)
 *   - Dictionary / brute-force attack on install codes
 *   - Install code generation from partial information
 */

#ifndef ZIGBLADE_ZIGBEE_INSTALL_CODE_H
#define ZIGBLADE_ZIGBEE_INSTALL_CODE_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Install code lengths supported by Zigbee 3.0 (bytes, including 2-byte CRC) */
#define INSTALL_CODE_LEN_6      6   /**< 4 bytes code + 2 CRC */
#define INSTALL_CODE_LEN_8      8   /**< 6 bytes code + 2 CRC */
#define INSTALL_CODE_LEN_12    12   /**< 10 bytes code + 2 CRC */
#define INSTALL_CODE_LEN_16    16   /**< 14 bytes code + 2 CRC */
#define INSTALL_CODE_LEN_18    18   /**< 16 bytes code + 2 CRC (full-length) */

#define INSTALL_CODE_MAX_LEN   18

/** Maximum dictionary entries for brute-force */
#define INSTALL_CODE_DICT_MAX  256

/** Well-known default Zigbee trust center link key (ZigBeeAlliance09) */
extern const uint8_t ZIGBEE_DEFAULT_TC_LINK_KEY[16];

/** Security mode detected for a network */
typedef enum {
    ZB_SEC_MODE_UNKNOWN = 0,       /**< Cannot determine security mode   */
    ZB_SEC_MODE_DEFAULT_KEY,       /**< Uses default ZigBeeAlliance09    */
    ZB_SEC_MODE_INSTALL_CODE,      /**< Uses per-device install codes    */
    ZB_SEC_MODE_OPEN,              /**< No security / open joining       */
} zigbee_security_mode_t;

/** Result from an install code brute-force attempt */
typedef struct {
    bool     found;                /**< true if a valid code was found   */
    uint8_t  install_code[INSTALL_CODE_MAX_LEN];
    uint8_t  code_len;             /**< Length of the found code         */
    uint8_t  derived_key[16];      /**< AES-128 link key from MMO hash  */
    uint32_t attempts;             /**< Number of codes tried            */
    uint32_t elapsed_ms;           /**< Wall time spent                  */
} install_code_result_t;

/** Callback for brute-force progress reporting */
typedef void (*install_code_progress_cb_t)(uint32_t attempts, uint32_t total);

/**
 * @brief Validate an install code by checking its CRC-16/X.25 checksum.
 *
 * The last 2 bytes of the code must match the CRC-16/CCITT of the
 * preceding bytes (per Zigbee CCB 2321).
 *
 * @param code     Install code bytes (including trailing 2-byte CRC).
 * @param code_len Total length (6, 8, 12, 16, or 18).
 * @return true if CRC is valid.
 */
bool zigbee_install_code_validate_crc(const uint8_t *code, uint8_t code_len);

/**
 * @brief Compute the CRC-16/X.25 for an install code body.
 *
 * @param data     Code body (without CRC).
 * @param data_len Length of the body.
 * @return 16-bit CRC value (little-endian as stored in code).
 */
uint16_t zigbee_install_code_compute_crc(const uint8_t *data, uint8_t data_len);

/**
 * @brief Derive a link key from an install code using Matyas-Meyer-Oseas hash.
 *
 * Implements the MMO hash specified in Zigbee spec B.6 to turn an
 * install code into a 128-bit AES key suitable for trust center use.
 *
 * @param[in]  code      Install code bytes (including CRC).
 * @param[in]  code_len  Code length (6, 8, 12, 16, or 18).
 * @param[out] key_out   Output 16-byte derived link key.
 * @return ESP_OK on success.
 */
esp_err_t zigbee_install_code_to_key(const uint8_t *code,
                                     uint8_t code_len,
                                     uint8_t *key_out);

/**
 * @brief Detect whether a network uses default key or install codes.
 *
 * Inspects the transport-key command captured during joining and
 * attempts decryption with the default ZigBeeAlliance09 key.  If
 * decryption succeeds the network uses the default key; otherwise it
 * likely uses install codes.
 *
 * @param[in] transport_key_frame  Raw APS Transport Key frame bytes.
 * @param[in] frame_len            Frame length.
 * @param[in] src_ext_addr         8-byte source IEEE address for nonce.
 * @param[in] frame_counter        NWK frame counter from the frame.
 * @return Detected security mode.
 */
zigbee_security_mode_t zigbee_detect_security_mode(
    const uint8_t *transport_key_frame,
    uint8_t frame_len,
    const uint8_t *src_ext_addr,
    uint32_t frame_counter);

/**
 * @brief Try a dictionary of common install codes against a captured frame.
 *
 * For each dictionary entry, derives the link key via MMO hash, then
 * attempts to decrypt the provided encrypted APS payload.  Stops on
 * the first successful decryption.
 *
 * @param[in]  enc_payload   Encrypted APS payload bytes.
 * @param[in]  enc_len       Encrypted payload length (without MIC).
 * @param[in]  mic           MIC bytes from the frame.
 * @param[in]  mic_len       MIC length (4, 8, or 16).
 * @param[in]  src_ext_addr  8-byte source IEEE address for nonce.
 * @param[in]  frame_counter Frame counter for nonce derivation.
 * @param[in]  sec_level     Security level byte.
 * @param[in]  aad           Additional authenticated data (headers).
 * @param[in]  aad_len       AAD length.
 * @param[out] result        Output result (found code + derived key).
 * @param[in]  progress_cb   Optional progress callback (may be NULL).
 * @return ESP_OK if a match was found, ESP_ERR_NOT_FOUND otherwise.
 */
esp_err_t zigbee_install_code_dict_attack(
    const uint8_t *enc_payload,
    uint8_t enc_len,
    const uint8_t *mic,
    uint8_t mic_len,
    const uint8_t *src_ext_addr,
    uint32_t frame_counter,
    uint8_t sec_level,
    const uint8_t *aad,
    uint8_t aad_len,
    install_code_result_t *result,
    install_code_progress_cb_t progress_cb);

/**
 * @brief Generate candidate install codes from partial information.
 *
 * Given a partial install code (some bytes known, others zero), brute
 * forces the unknown bytes and validates via CRC.  Any CRC-valid
 * candidate is tested for decryption against the provided ciphertext.
 *
 * @param[in]  partial       Partial code (unknown bytes set to 0x00).
 * @param[in]  known_mask    Bitmask: 1 = byte is known, 0 = brute-force.
 * @param[in]  code_len      Total code length (including CRC).
 * @param[in]  enc_payload   Encrypted payload for validation (may be NULL).
 * @param[in]  enc_len       Encrypted payload length.
 * @param[in]  mic           MIC for validation (may be NULL).
 * @param[in]  mic_len       MIC length.
 * @param[in]  src_ext_addr  Source IEEE address.
 * @param[in]  frame_counter Frame counter.
 * @param[in]  sec_level     Security level.
 * @param[out] result        Output result.
 * @return ESP_OK if a valid code was found, ESP_ERR_NOT_FOUND otherwise.
 */
esp_err_t zigbee_install_code_brute_partial(
    const uint8_t *partial,
    uint32_t known_mask,
    uint8_t code_len,
    const uint8_t *enc_payload,
    uint8_t enc_len,
    const uint8_t *mic,
    uint8_t mic_len,
    const uint8_t *src_ext_addr,
    uint32_t frame_counter,
    uint8_t sec_level,
    install_code_result_t *result);

#ifdef __cplusplus
}
#endif

#endif /* ZIGBLADE_ZIGBEE_INSTALL_CODE_H */
