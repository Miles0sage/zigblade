/**
 * @file crypto.c
 * @brief AES-128 CCM* for Zigbee security using ESP32-H2 hardware AES.
 *
 * CCM* (Counter with CBC-MAC, star variant) as specified in
 * IEEE 802.15.4-2015 Annex B and Zigbee spec section 4.5.2.
 *
 * Uses mbedtls (backed by ESP32-H2 hardware accelerator) for the
 * underlying AES-128 block cipher operations.
 */

#include "crypto.h"

#include <string.h>
#include "esp_log.h"
#include "mbedtls/aes.h"
#include "mbedtls/ccm.h"

static const char *TAG = "zigblade_crypto";

/* ── MIC length lookup ────────────────────────────────────────────── */

uint8_t zigbee_mic_len(uint8_t security_level)
{
    switch (security_level) {
    case ZIGBEE_SEC_LEVEL_NONE:
    case ZIGBEE_SEC_LEVEL_ENC:
        return 0;
    case ZIGBEE_SEC_LEVEL_MIC_32:
    case ZIGBEE_SEC_LEVEL_ENC_MIC_32:
        return 4;
    case ZIGBEE_SEC_LEVEL_MIC_64:
    case ZIGBEE_SEC_LEVEL_ENC_MIC_64:
        return 8;
    case ZIGBEE_SEC_LEVEL_MIC_128:
    case ZIGBEE_SEC_LEVEL_ENC_MIC_128:
        return 16;
    default:
        return 0;
    }
}

/* ── Nonce derivation ─────────────────────────────────────────────── */

esp_err_t zigbee_derive_nonce(const uint8_t *src_ext_addr,
                              uint32_t frame_counter,
                              uint8_t security_level,
                              uint8_t *nonce)
{
    if (src_ext_addr == NULL || nonce == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    /*
     * Zigbee CCM* nonce (13 bytes):
     *   Bytes 0-7:  Source IEEE address (8 bytes, as stored — little-endian)
     *   Bytes 8-11: Frame counter (4 bytes, little-endian)
     *   Byte 12:    Security level
     *
     * Note: The Zigbee spec stores the source address in the nonce
     * in the same byte order as the IEEE extended address field.
     */
    memcpy(&nonce[0], src_ext_addr, 8);

    nonce[8]  = (uint8_t)(frame_counter >> 0);
    nonce[9]  = (uint8_t)(frame_counter >> 8);
    nonce[10] = (uint8_t)(frame_counter >> 16);
    nonce[11] = (uint8_t)(frame_counter >> 24);
    nonce[12] = security_level;

    return ESP_OK;
}

/* ── AES-128 CCM* encrypt ─────────────────────────────────────────── */

esp_err_t zigbee_aes_ccm_encrypt(const uint8_t *key,
                                 const uint8_t *nonce,
                                 uint8_t *payload,
                                 uint16_t len,
                                 const uint8_t *aad,
                                 uint16_t aad_len,
                                 uint8_t *mic,
                                 uint8_t mic_len)
{
    if (key == NULL || nonce == NULL || mic == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (mic_len != 0 && mic_len != 4 && mic_len != 8 && mic_len != 16) {
        ESP_LOGE(TAG, "Invalid MIC length: %d", mic_len);
        return ESP_ERR_INVALID_ARG;
    }

    mbedtls_ccm_context ctx;
    mbedtls_ccm_init(&ctx);

    int ret = mbedtls_ccm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES,
                                 key, ZIGBEE_KEY_LEN * 8);
    if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls_ccm_setkey failed: -0x%04X", (unsigned)-ret);
        mbedtls_ccm_free(&ctx);
        return ESP_FAIL;
    }

    /*
     * mbedtls_ccm_encrypt_and_tag:
     *   - iv = nonce (13 bytes for CCM* with L=2)
     *   - iv_len = 13
     *   - aad, aad_len = additional authenticated data
     *   - input = plaintext
     *   - output = ciphertext (can be same buffer)
     *   - tag = MIC output
     *   - tag_len = MIC length
     *
     * If len == 0 (authentication only), payload can be NULL.
     */
    uint8_t *input_buf = NULL;
    uint8_t temp_buf[128];

    if (len > 0) {
        if (len > sizeof(temp_buf)) {
            ESP_LOGE(TAG, "Payload too long for encrypt: %d", len);
            mbedtls_ccm_free(&ctx);
            return ESP_ERR_INVALID_SIZE;
        }
        /* Copy plaintext; mbedtls needs separate in/out or same buffer */
        memcpy(temp_buf, payload, len);
        input_buf = temp_buf;
    }

    uint8_t tag[16] = {0};
    ret = mbedtls_ccm_encrypt_and_tag(&ctx,
                                      len,
                                      nonce, ZIGBEE_NONCE_LEN,
                                      aad, aad_len,
                                      input_buf, payload,
                                      tag, mic_len);
    mbedtls_ccm_free(&ctx);

    if (ret != 0) {
        ESP_LOGE(TAG, "CCM encrypt failed: -0x%04X", (unsigned)-ret);
        return ESP_FAIL;
    }

    if (mic_len > 0) {
        memcpy(mic, tag, mic_len);
    }

    return ESP_OK;
}

/* ── AES-128 CCM* decrypt ─────────────────────────────────────────── */

esp_err_t zigblade_aes_ccm_decrypt(const uint8_t *key,
                                   const uint8_t *nonce,
                                   uint8_t *payload,
                                   uint16_t len,
                                   const uint8_t *aad,
                                   uint16_t aad_len,
                                   const uint8_t *mic,
                                   uint8_t mic_len)
{
    if (key == NULL || nonce == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (mic_len != 0 && mic_len != 4 && mic_len != 8 && mic_len != 16) {
        ESP_LOGE(TAG, "Invalid MIC length: %d", mic_len);
        return ESP_ERR_INVALID_ARG;
    }

    mbedtls_ccm_context ctx;
    mbedtls_ccm_init(&ctx);

    int ret = mbedtls_ccm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES,
                                 key, ZIGBEE_KEY_LEN * 8);
    if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls_ccm_setkey failed: -0x%04X", (unsigned)-ret);
        mbedtls_ccm_free(&ctx);
        return ESP_FAIL;
    }

    uint8_t temp_buf[128];
    uint8_t *input_buf = NULL;

    if (len > 0) {
        if (len > sizeof(temp_buf)) {
            ESP_LOGE(TAG, "Payload too long for decrypt: %d", len);
            mbedtls_ccm_free(&ctx);
            return ESP_ERR_INVALID_SIZE;
        }
        memcpy(temp_buf, payload, len);
        input_buf = temp_buf;
    }

    ret = mbedtls_ccm_auth_decrypt(&ctx,
                                   len,
                                   nonce, ZIGBEE_NONCE_LEN,
                                   aad, aad_len,
                                   input_buf, payload,
                                   mic, mic_len);
    mbedtls_ccm_free(&ctx);

    if (ret == MBEDTLS_ERR_CCM_AUTH_FAILED) {
        ESP_LOGW(TAG, "CCM MIC verification failed");
        return ESP_ERR_INVALID_STATE;
    }
    if (ret != 0) {
        ESP_LOGE(TAG, "CCM decrypt failed: -0x%04X", (unsigned)-ret);
        return ESP_FAIL;
    }

    return ESP_OK;
}

/* ── Raw AES-128 ECB ──────────────────────────────────────────────── */

esp_err_t zigbee_aes_ecb_encrypt(const uint8_t *key,
                                 const uint8_t *input,
                                 uint8_t *output)
{
    if (key == NULL || input == NULL || output == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);

    int ret = mbedtls_aes_setkey_enc(&ctx, key, ZIGBEE_KEY_LEN * 8);
    if (ret != 0) {
        mbedtls_aes_free(&ctx);
        return ESP_FAIL;
    }

    ret = mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, input, output);
    mbedtls_aes_free(&ctx);

    return (ret == 0) ? ESP_OK : ESP_FAIL;
}
