/**
 * @file frame_parser.c
 * @brief Multi-layer IEEE 802.15.4 / Zigbee frame parser.
 */

#include "frame_parser.h"

#include <string.h>
#include "esp_log.h"

static const char *TAG = "frame_parser";

/* ── Helpers ──────────────────────────────────────────────────────── */

/** Read uint16 little-endian from buffer. */
static inline uint16_t rd16(const uint8_t *p)
{
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

/** Read uint32 little-endian from buffer. */
static inline uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0]       | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* ── MAC parser ───────────────────────────────────────────────────── */

esp_err_t frame_parse_mac(const uint8_t *data, uint8_t len, mac_header_t *mac)
{
    if (data == NULL || mac == NULL || len < 2) {
        return ESP_ERR_INVALID_ARG;
    }

    memset(mac, 0, sizeof(*mac));

    uint16_t fcf = rd16(data);
    mac->fcf = fcf;

    /* Decode FCF fields per IEEE 802.15.4-2015 section 7.2.1 */
    mac->frame_type       = (fcf >> 0) & 0x07;
    mac->security_enabled = (fcf >> 3) & 0x01;
    mac->frame_pending    = (fcf >> 4) & 0x01;
    mac->ack_request      = (fcf >> 5) & 0x01;
    mac->pan_id_compress  = (fcf >> 6) & 0x01;
    mac->dst_addr_mode    = (fcf >> 10) & 0x03;
    mac->src_addr_mode    = (fcf >> 14) & 0x03;

    uint8_t pos = 2;

    /* Sequence number (not present in some 802.15.4e frames, but
       always present for Zigbee-relevant frame types 0-3) */
    if (pos >= len) return ESP_ERR_INVALID_SIZE;
    mac->seq_num = data[pos++];

    /* Destination PAN ID */
    if (mac->dst_addr_mode != IEEE802154_ADDR_MODE_NONE) {
        if (pos + 2 > len) return ESP_ERR_INVALID_SIZE;
        mac->dst_panid = rd16(&data[pos]);
        pos += 2;

        /* Destination address */
        if (mac->dst_addr_mode == IEEE802154_ADDR_MODE_SHORT) {
            if (pos + 2 > len) return ESP_ERR_INVALID_SIZE;
            mac->dst_short_addr = rd16(&data[pos]);
            pos += 2;
        } else if (mac->dst_addr_mode == IEEE802154_ADDR_MODE_LONG) {
            if (pos + 8 > len) return ESP_ERR_INVALID_SIZE;
            memcpy(mac->dst_ext_addr, &data[pos], 8);
            pos += 8;
        }
    }

    /* Source PAN ID (omitted if PAN ID compression and dst PAN present) */
    if (mac->src_addr_mode != IEEE802154_ADDR_MODE_NONE) {
        if (!mac->pan_id_compress) {
            if (pos + 2 > len) return ESP_ERR_INVALID_SIZE;
            mac->src_panid = rd16(&data[pos]);
            pos += 2;
        } else {
            mac->src_panid = mac->dst_panid;
        }

        /* Source address */
        if (mac->src_addr_mode == IEEE802154_ADDR_MODE_SHORT) {
            if (pos + 2 > len) return ESP_ERR_INVALID_SIZE;
            mac->src_short_addr = rd16(&data[pos]);
            pos += 2;
        } else if (mac->src_addr_mode == IEEE802154_ADDR_MODE_LONG) {
            if (pos + 8 > len) return ESP_ERR_INVALID_SIZE;
            memcpy(mac->src_ext_addr, &data[pos], 8);
            pos += 8;
        }
    }

    /* Auxiliary security header */
    if (mac->security_enabled) {
        if (pos + 1 > len) return ESP_ERR_INVALID_SIZE;
        uint8_t sec_ctrl = data[pos++];
        mac->security_level = sec_ctrl & 0x07;
        mac->key_id_mode    = (sec_ctrl >> 3) & 0x03;

        if (pos + 4 > len) return ESP_ERR_INVALID_SIZE;
        mac->frame_counter = rd32(&data[pos]);
        pos += 4;

        switch (mac->key_id_mode) {
        case 0: /* implicit */
            break;
        case 1: /* key index only */
            if (pos + 1 > len) return ESP_ERR_INVALID_SIZE;
            mac->key_index = data[pos++];
            break;
        case 2: /* 4-byte key source + index */
            if (pos + 5 > len) return ESP_ERR_INVALID_SIZE;
            memcpy(mac->key_source, &data[pos], 4);
            pos += 4;
            mac->key_index = data[pos++];
            break;
        case 3: /* 8-byte key source + index */
            if (pos + 9 > len) return ESP_ERR_INVALID_SIZE;
            memcpy(mac->key_source, &data[pos], 8);
            pos += 8;
            mac->key_index = data[pos++];
            break;
        }
    }

    mac->header_len = pos;
    return ESP_OK;
}

/* ── NWK parser ───────────────────────────────────────────────────── */

esp_err_t frame_parse_nwk(const uint8_t *data, uint8_t len, nwk_header_t *nwk)
{
    if (data == NULL || nwk == NULL || len < 8) {
        return ESP_ERR_INVALID_ARG;
    }

    memset(nwk, 0, sizeof(*nwk));

    uint16_t fc = rd16(data);
    nwk->frame_control    = fc;
    nwk->frame_type       = (fc >> 0) & 0x03;
    nwk->protocol_version = (fc >> 2) & 0x0F;
    nwk->discover_route   = (fc >> 6) & 0x03;
    nwk->multicast        = (fc >> 8) & 0x01;
    nwk->security         = (fc >> 9) & 0x01;
    nwk->source_route     = (fc >> 10) & 0x01;
    nwk->dst_ieee_present = (fc >> 11) & 0x01;
    nwk->src_ieee_present = (fc >> 12) & 0x01;

    uint8_t pos = 2;

    /* NWK destination and source short addresses */
    if (pos + 4 > len) return ESP_ERR_INVALID_SIZE;
    nwk->dst_addr = rd16(&data[pos]); pos += 2;
    nwk->src_addr = rd16(&data[pos]); pos += 2;

    /* Radius and sequence number */
    if (pos + 2 > len) return ESP_ERR_INVALID_SIZE;
    nwk->radius  = data[pos++];
    nwk->seq_num = data[pos++];

    /* Optional destination IEEE address */
    if (nwk->dst_ieee_present) {
        if (pos + 8 > len) return ESP_ERR_INVALID_SIZE;
        memcpy(nwk->dst_ieee, &data[pos], 8);
        pos += 8;
    }

    /* Optional source IEEE address */
    if (nwk->src_ieee_present) {
        if (pos + 8 > len) return ESP_ERR_INVALID_SIZE;
        memcpy(nwk->src_ieee, &data[pos], 8);
        pos += 8;
    }

    /* Multicast control (if multicast flag set) */
    if (nwk->multicast) {
        if (pos + 1 > len) return ESP_ERR_INVALID_SIZE;
        pos += 1; /* skip multicast control byte */
    }

    /* Source route sub-frame (if source_route flag set) */
    if (nwk->source_route) {
        if (pos + 2 > len) return ESP_ERR_INVALID_SIZE;
        uint8_t relay_count = data[pos++];
        uint8_t relay_index = data[pos++];
        (void)relay_index;
        uint8_t relay_bytes = relay_count * 2;
        if (pos + relay_bytes > len) return ESP_ERR_INVALID_SIZE;
        pos += relay_bytes;
    }

    /* NWK auxiliary security header */
    if (nwk->security) {
        if (pos + 1 > len) return ESP_ERR_INVALID_SIZE;
        uint8_t sec_ctrl = data[pos++];
        nwk->sec_level      = sec_ctrl & 0x07;
        nwk->sec_key_id_mode = (sec_ctrl >> 3) & 0x03;

        if (pos + 4 > len) return ESP_ERR_INVALID_SIZE;
        nwk->sec_frame_counter = rd32(&data[pos]);
        pos += 4;

        /* Extended nonce: source IEEE address (if not already in header) */
        if ((sec_ctrl >> 5) & 0x01) {
            if (pos + 8 > len) return ESP_ERR_INVALID_SIZE;
            /* Use as source IEEE if not present in NWK header */
            if (!nwk->src_ieee_present) {
                memcpy(nwk->src_ieee, &data[pos], 8);
            }
            pos += 8;
        }

        switch (nwk->sec_key_id_mode) {
        case 0: break;
        case 1:
            if (pos + 1 > len) return ESP_ERR_INVALID_SIZE;
            nwk->sec_key_seq_num = data[pos++];
            break;
        case 2:
            if (pos + 5 > len) return ESP_ERR_INVALID_SIZE;
            memcpy(nwk->sec_key_source, &data[pos], 4);
            pos += 4;
            nwk->sec_key_seq_num = data[pos++];
            break;
        case 3:
            if (pos + 9 > len) return ESP_ERR_INVALID_SIZE;
            memcpy(nwk->sec_key_source, &data[pos], 8);
            pos += 8;
            nwk->sec_key_seq_num = data[pos++];
            break;
        }
    }

    /* If this is a NWK command frame, grab the command ID */
    if (nwk->frame_type == ZB_NWK_FRAME_TYPE_CMD && pos < len) {
        nwk->nwk_cmd_id = data[pos];
        /* Don't advance pos — command byte is part of NWK payload */
    }

    nwk->header_len = pos;
    return ESP_OK;
}

/* ── APS parser ───────────────────────────────────────────────────── */

esp_err_t frame_parse_aps(const uint8_t *data, uint8_t len, aps_header_t *aps)
{
    if (data == NULL || aps == NULL || len < 1) {
        return ESP_ERR_INVALID_ARG;
    }

    memset(aps, 0, sizeof(*aps));

    uint8_t fc = data[0];
    aps->frame_control      = fc;
    aps->frame_type         = (fc >> 0) & 0x03;
    aps->delivery_mode      = (fc >> 2) & 0x03;
    aps->ack_format         = (fc >> 4) & 0x01;
    aps->security           = (fc >> 5) & 0x01;
    aps->ack_request        = (fc >> 6) & 0x01;
    aps->ext_header_present = (fc >> 7) & 0x01;

    uint8_t pos = 1;

    if (aps->frame_type == ZB_APS_FRAME_TYPE_DATA ||
        aps->frame_type == ZB_APS_FRAME_TYPE_ACK) {

        /* Destination endpoint (unicast/ack) or group (group delivery) */
        if (aps->delivery_mode == ZB_APS_DELIVERY_GROUP) {
            if (pos + 2 > len) return ESP_ERR_INVALID_SIZE;
            aps->group_addr = rd16(&data[pos]);
            pos += 2;
        } else if (aps->delivery_mode == ZB_APS_DELIVERY_UNICAST ||
                   aps->delivery_mode == ZB_APS_DELIVERY_INDIRECT) {
            if (pos + 1 > len) return ESP_ERR_INVALID_SIZE;
            aps->dst_endpoint = data[pos++];
        }

        /* Cluster ID and Profile ID */
        if (pos + 4 > len) return ESP_ERR_INVALID_SIZE;
        aps->cluster_id = rd16(&data[pos]); pos += 2;
        aps->profile_id = rd16(&data[pos]); pos += 2;

        /* Source endpoint */
        if (pos + 1 > len) return ESP_ERR_INVALID_SIZE;
        aps->src_endpoint = data[pos++];
    }

    /* APS counter */
    if (aps->frame_type != ZB_APS_FRAME_TYPE_INTER_PAN) {
        if (pos + 1 > len) return ESP_ERR_INVALID_SIZE;
        aps->aps_counter = data[pos++];
    }

    /* APS command ID (for command frames) */
    if (aps->frame_type == ZB_APS_FRAME_TYPE_CMD) {
        if (pos < len) {
            aps->aps_cmd_id = data[pos];
            /* Don't advance — command byte is payload start */
        }
    }

    aps->header_len = pos;
    return ESP_OK;
}

/* ── ZCL parser ───────────────────────────────────────────────────── */

esp_err_t frame_parse_zcl(const uint8_t *data, uint8_t len, zcl_header_t *zcl)
{
    if (data == NULL || zcl == NULL || len < 3) {
        return ESP_ERR_INVALID_ARG;
    }

    memset(zcl, 0, sizeof(*zcl));

    uint8_t fc = data[0];
    zcl->frame_control          = fc;
    zcl->frame_type             = (fc >> 0) & 0x03;
    zcl->manufacturer_specific  = (fc >> 2) & 0x01;
    zcl->direction              = (fc >> 3) & 0x01;
    zcl->disable_default_rsp    = (fc >> 4) & 0x01;

    uint8_t pos = 1;

    /* Manufacturer code (optional 2 bytes) */
    if (zcl->manufacturer_specific) {
        if (pos + 2 > len) return ESP_ERR_INVALID_SIZE;
        zcl->manufacturer_code = rd16(&data[pos]);
        pos += 2;
    }

    /* Transaction sequence number */
    if (pos + 1 > len) return ESP_ERR_INVALID_SIZE;
    zcl->seq_num = data[pos++];

    /* Command ID */
    if (pos + 1 > len) return ESP_ERR_INVALID_SIZE;
    zcl->command_id = data[pos++];

    zcl->header_len = pos;
    return ESP_OK;
}

/* ── Full-frame parser ────────────────────────────────────────────── */

esp_err_t frame_parse(const uint8_t *data, uint8_t len, parsed_frame_t *frame)
{
    if (data == NULL || frame == NULL || len == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    memset(frame, 0, sizeof(*frame));

    /* Store raw frame */
    uint8_t copy_len = (len > sizeof(frame->raw)) ? sizeof(frame->raw) : len;
    memcpy(frame->raw, data, copy_len);
    frame->raw_len = copy_len;

    /* --- Layer 1: MAC --- */
    esp_err_t err = frame_parse_mac(data, len, &frame->mac);
    if (err != ESP_OK) {
        ESP_LOGD(TAG, "MAC parse failed: %s", esp_err_to_name(err));
        return err;
    }
    frame->mac_valid = true;

    uint8_t mac_hdr_len = frame->mac.header_len;
    if (mac_hdr_len >= len) {
        /* No payload beyond MAC header */
        frame->mac_payload     = NULL;
        frame->mac_payload_len = 0;
        return ESP_OK;
    }
    frame->mac_payload     = &frame->raw[mac_hdr_len];
    frame->mac_payload_len = len - mac_hdr_len;

    /* Only attempt NWK parsing on data frames */
    if (frame->mac.frame_type != IEEE802154_FRAME_TYPE_DATA) {
        return ESP_OK;
    }

    /* --- Layer 2: NWK --- */
    err = frame_parse_nwk(frame->mac_payload, frame->mac_payload_len, &frame->nwk);
    if (err != ESP_OK) {
        ESP_LOGD(TAG, "NWK parse failed: %s", esp_err_to_name(err));
        return ESP_OK; /* MAC was valid, just no NWK */
    }
    frame->nwk_valid = true;

    uint8_t nwk_hdr_len = frame->nwk.header_len;
    if (nwk_hdr_len >= frame->mac_payload_len) {
        frame->nwk_payload     = NULL;
        frame->nwk_payload_len = 0;
        return ESP_OK;
    }
    frame->nwk_payload     = frame->mac_payload + nwk_hdr_len;
    frame->nwk_payload_len = frame->mac_payload_len - nwk_hdr_len;

    /* If NWK security is enabled, payload is encrypted — stop here */
    if (frame->nwk.security) {
        ESP_LOGD(TAG, "NWK encrypted, skipping APS/ZCL parse");
        return ESP_OK;
    }

    /* NWK command frames don't carry APS */
    if (frame->nwk.frame_type != ZB_NWK_FRAME_TYPE_DATA) {
        return ESP_OK;
    }

    /* --- Layer 3: APS --- */
    err = frame_parse_aps(frame->nwk_payload, frame->nwk_payload_len, &frame->aps);
    if (err != ESP_OK) {
        ESP_LOGD(TAG, "APS parse failed: %s", esp_err_to_name(err));
        return ESP_OK;
    }
    frame->aps_valid = true;

    uint8_t aps_hdr_len = frame->aps.header_len;
    if (aps_hdr_len >= frame->nwk_payload_len) {
        frame->aps_payload     = NULL;
        frame->aps_payload_len = 0;
        return ESP_OK;
    }
    frame->aps_payload     = frame->nwk_payload + aps_hdr_len;
    frame->aps_payload_len = frame->nwk_payload_len - aps_hdr_len;

    /* APS command frames and encrypted APS don't carry ZCL */
    if (frame->aps.frame_type != ZB_APS_FRAME_TYPE_DATA || frame->aps.security) {
        return ESP_OK;
    }

    /* --- Layer 4: ZCL --- */
    err = frame_parse_zcl(frame->aps_payload, frame->aps_payload_len, &frame->zcl);
    if (err != ESP_OK) {
        ESP_LOGD(TAG, "ZCL parse failed: %s", esp_err_to_name(err));
        return ESP_OK;
    }
    frame->zcl_valid = true;

    uint8_t zcl_hdr_len = frame->zcl.header_len;
    if (zcl_hdr_len >= frame->aps_payload_len) {
        frame->zcl_payload     = NULL;
        frame->zcl_payload_len = 0;
    } else {
        frame->zcl_payload     = frame->aps_payload + zcl_hdr_len;
        frame->zcl_payload_len = frame->aps_payload_len - zcl_hdr_len;
    }

    return ESP_OK;
}

/* ── Human-readable strings ───────────────────────────────────────── */

const char *frame_type_str(uint8_t frame_type)
{
    switch (frame_type) {
    case IEEE802154_FRAME_TYPE_BEACON: return "Beacon";
    case IEEE802154_FRAME_TYPE_DATA:   return "Data";
    case IEEE802154_FRAME_TYPE_ACK:    return "ACK";
    case IEEE802154_FRAME_TYPE_CMD:    return "MAC Command";
    default:                           return "Unknown";
    }
}

const char *nwk_cmd_str(uint8_t cmd_id)
{
    switch (cmd_id) {
    case ZB_NWK_CMD_ROUTE_REQ:     return "Route Request";
    case ZB_NWK_CMD_ROUTE_REPLY:   return "Route Reply";
    case ZB_NWK_CMD_NWK_STATUS:    return "Network Status";
    case ZB_NWK_CMD_LEAVE:         return "Leave";
    case ZB_NWK_CMD_ROUTE_RECORD:  return "Route Record";
    case ZB_NWK_CMD_REJOIN_REQ:    return "Rejoin Request";
    case ZB_NWK_CMD_REJOIN_RSP:    return "Rejoin Response";
    case ZB_NWK_CMD_LINK_STATUS:   return "Link Status";
    case ZB_NWK_CMD_NWK_REPORT:    return "Network Report";
    case ZB_NWK_CMD_NWK_UPDATE:    return "Network Update";
    default:                       return "Unknown NWK Cmd";
    }
}

const char *aps_cmd_str(uint8_t cmd_id)
{
    switch (cmd_id) {
    case ZB_APS_CMD_TRANSPORT_KEY:  return "Transport Key";
    case ZB_APS_CMD_UPDATE_DEVICE:  return "Update Device";
    case ZB_APS_CMD_REMOVE_DEVICE:  return "Remove Device";
    case ZB_APS_CMD_REQUEST_KEY:    return "Request Key";
    case ZB_APS_CMD_SWITCH_KEY:     return "Switch Key";
    case ZB_APS_CMD_TUNNEL:         return "Tunnel";
    case ZB_APS_CMD_VERIFY_KEY:     return "Verify Key";
    case ZB_APS_CMD_CONFIRM_KEY:    return "Confirm Key";
    default:                        return "Unknown APS Cmd";
    }
}
