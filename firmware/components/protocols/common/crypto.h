/**
 * @file crypto.h
 * @brief AES-128 CCM* encryption/decryption for Zigbee security.
 *
 * Implements the CCM* mode used by IEEE 802.15.4 and Zigbee security
 * at both the NWK and APS layers, using the ESP32-H2 hardware AES
 * accelerator via mbedtls.
 */

#ifndef ZIGBLADE_CRYPTO_H
#define ZIGBLADE_CRYPTO_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Zigbee / 802.15.4 security levels */
#define ZIGBEE_SEC_LEVEL_NONE           0x00
#define ZIGBEE_SEC_LEVEL_MIC_32         0x01
#define ZIGBEE_SEC_LEVEL_MIC_64         0x02
#define ZIGBEE_SEC_LEVEL_MIC_128        0x03
#define ZIGBEE_SEC_LEVEL_ENC            0x04
#define ZIGBEE_SEC_LEVEL_ENC_MIC_32     0x05
#define ZIGBEE_SEC_LEVEL_ENC_MIC_64     0x06
#define ZIGBEE_SEC_LEVEL_ENC_MIC_128    0x07

/** AES-128 key size */
#define ZIGBEE_KEY_LEN                  16

/** CCM* nonce length (13 bytes per IEEE 802.15.4 / Zigbee spec) */
#define ZIGBEE_NONCE_LEN                13

/** Maximum MIC length */
#define ZIGBEE_MAX_MIC_LEN              16

/**
 * @brief Get the MIC length for a given security level.
 *
 * @param security_level  Security level (0-7).
 * @return MIC length in bytes (0, 4, 8, or 16).
 */
uint8_t zigbee_mic_len(uint8_t security_level);

/**
 * @brief Derive the 13-byte CCM* nonce from frame parameters.
 *
 * Per Zigbee spec (section 4.5.2.2):
 *   Nonce = SourceAddress(8) || FrameCounter(4) || SecurityLevel(1)
 *
 * @param[in]  src_ext_addr     8-byte source IEEE address (little-endian).
 * @param[in]  frame_counter    32-bit frame counter.
 * @param[in]  security_level   Security level byte.
 * @param[out] nonce            Output 13-byte nonce buffer.
 * @return ESP_OK on success, ESP_ERR_INVALID_ARG if pointers are NULL.
 */
esp_err_t zigbee_derive_nonce(const uint8_t *src_ext_addr,
                              uint32_t frame_counter,
                              uint8_t security_level,
                              uint8_t *nonce);

/**
 * @brief Encrypt payload and compute MIC using AES-128 CCM*.
 *
 * @param[in]     key       16-byte AES key.
 * @param[in]     nonce     13-byte nonce.
 * @param[in,out] payload   Plaintext in, ciphertext out.
 * @param[in]     len       Payload length.
 * @param[in]     aad       Additional authenticated data (MAC/NWK headers).
 * @param[in]     aad_len   AAD length.
 * @param[out]    mic       Output MIC buffer.
 * @param[in]     mic_len   Desired MIC length (4, 8, or 16).
 * @return ESP_OK on success.
 */
esp_err_t zigbee_aes_ccm_encrypt(const uint8_t *key,
                                 const uint8_t *nonce,
                                 uint8_t *payload,
                                 uint16_t len,
                                 const uint8_t *aad,
                                 uint16_t aad_len,
                                 uint8_t *mic,
                                 uint8_t mic_len);

/**
 * @brief Decrypt payload and verify MIC using AES-128 CCM*.
 *
 * @param[in]     key       16-byte AES key.
 * @param[in]     nonce     13-byte nonce.
 * @param[in,out] payload   Ciphertext in, plaintext out.
 * @param[in]     len       Payload length (without MIC).
 * @param[in]     aad       Additional authenticated data.
 * @param[in]     aad_len   AAD length.
 * @param[in]     mic       Expected MIC to verify.
 * @param[in]     mic_len   MIC length (4, 8, or 16).
 * @return ESP_OK on success, ESP_ERR_INVALID_STATE if MIC mismatch.
 */
esp_err_t zigbee_aes_ccm_decrypt(const uint8_t *key,
                                 const uint8_t *nonce,
                                 uint8_t *payload,
                                 uint16_t len,
                                 const uint8_t *aad,
                                 uint16_t aad_len,
                                 const uint8_t *mic,
                                 uint8_t mic_len);

/**
 * @brief Raw AES-128 ECB block encrypt (for key derivation/hash).
 *
 * @param[in]  key    16-byte key.
 * @param[in]  input  16-byte plaintext block.
 * @param[out] output 16-byte ciphertext block.
 * @return ESP_OK on success.
 */
esp_err_t zigbee_aes_ecb_encrypt(const uint8_t *key,
                                 const uint8_t *input,
                                 uint8_t *output);

#ifdef __cplusplus
}
#endif

#endif /* ZIGBLADE_CRYPTO_H */
