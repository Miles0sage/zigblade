/**
 * @file frame_parser.h
 * @brief IEEE 802.15.4 / Zigbee multi-layer frame parser.
 *
 * Parses raw 802.15.4 frames into structured representations covering:
 *   - IEEE 802.15.4 MAC layer
 *   - Zigbee NWK layer
 *   - Zigbee APS layer
 *   - Zigbee ZCL layer
 */

#ifndef ZIGBLADE_FRAME_PARSER_H
#define ZIGBLADE_FRAME_PARSER_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── IEEE 802.15.4 MAC constants ──────────────────────────────────── */

/** Frame types (FCF bits 0-2) */
#define IEEE802154_FRAME_TYPE_BEACON    0x00
#define IEEE802154_FRAME_TYPE_DATA      0x01
#define IEEE802154_FRAME_TYPE_ACK       0x02
#define IEEE802154_FRAME_TYPE_CMD       0x03

/** Addressing modes (FCF bits 10-11 dst, 14-15 src) */
#define IEEE802154_ADDR_MODE_NONE       0x00
#define IEEE802154_ADDR_MODE_SHORT      0x02
#define IEEE802154_ADDR_MODE_LONG       0x03

/* ── Zigbee NWK constants ─────────────────────────────────────────── */

#define ZB_NWK_FRAME_TYPE_DATA          0x00
#define ZB_NWK_FRAME_TYPE_CMD           0x01
#define ZB_NWK_FRAME_TYPE_INTER_PAN     0x03

#define ZB_NWK_CMD_ROUTE_REQ            0x01
#define ZB_NWK_CMD_ROUTE_REPLY          0x02
#define ZB_NWK_CMD_NWK_STATUS           0x03
#define ZB_NWK_CMD_LEAVE                0x04
#define ZB_NWK_CMD_ROUTE_RECORD         0x05
#define ZB_NWK_CMD_REJOIN_REQ           0x06
#define ZB_NWK_CMD_REJOIN_RSP           0x07
#define ZB_NWK_CMD_LINK_STATUS          0x08
#define ZB_NWK_CMD_NWK_REPORT           0x09
#define ZB_NWK_CMD_NWK_UPDATE           0x0A

/* ── Zigbee APS constants ─────────────────────────────────────────── */

#define ZB_APS_FRAME_TYPE_DATA          0x00
#define ZB_APS_FRAME_TYPE_CMD           0x01
#define ZB_APS_FRAME_TYPE_ACK           0x02
#define ZB_APS_FRAME_TYPE_INTER_PAN     0x03

#define ZB_APS_DELIVERY_UNICAST         0x00
#define ZB_APS_DELIVERY_INDIRECT        0x01
#define ZB_APS_DELIVERY_BROADCAST       0x02
#define ZB_APS_DELIVERY_GROUP           0x03

/** APS command IDs */
#define ZB_APS_CMD_TRANSPORT_KEY        0x05
#define ZB_APS_CMD_UPDATE_DEVICE        0x06
#define ZB_APS_CMD_REMOVE_DEVICE        0x07
#define ZB_APS_CMD_REQUEST_KEY          0x08
#define ZB_APS_CMD_SWITCH_KEY           0x09
#define ZB_APS_CMD_TUNNEL               0x0E
#define ZB_APS_CMD_VERIFY_KEY           0x0F
#define ZB_APS_CMD_CONFIRM_KEY          0x10

/* ── ZCL constants ────────────────────────────────────────────────── */

#define ZCL_FRAME_TYPE_GLOBAL           0x00
#define ZCL_FRAME_TYPE_CLUSTER          0x01

#define ZCL_DIR_CLIENT_TO_SERVER        0x00
#define ZCL_DIR_SERVER_TO_CLIENT        0x01

/** Common ZCL global commands */
#define ZCL_CMD_READ_ATTRIBUTES         0x00
#define ZCL_CMD_READ_ATTRIBUTES_RSP     0x01
#define ZCL_CMD_WRITE_ATTRIBUTES        0x02
#define ZCL_CMD_WRITE_ATTRIBUTES_RSP    0x04
#define ZCL_CMD_REPORT_ATTRIBUTES       0x0A
#define ZCL_CMD_DEFAULT_RSP             0x0B
#define ZCL_CMD_DISCOVER_ATTRIBUTES     0x0C

/* ── Parsed frame structures ──────────────────────────────────────── */

/** IEEE 802.15.4 MAC header */
typedef struct {
    uint16_t fcf;              /**< Frame Control Field                */
    uint8_t  seq_num;          /**< Sequence number                    */
    uint8_t  frame_type;       /**< Decoded frame type (0-3)           */
    bool     security_enabled; /**< Security sub-header present        */
    bool     frame_pending;    /**< More data pending                  */
    bool     ack_request;      /**< ACK requested                      */
    bool     pan_id_compress;  /**< PAN ID compression                 */

    /* Destination addressing */
    uint8_t  dst_addr_mode;
    uint16_t dst_panid;
    uint16_t dst_short_addr;
    uint8_t  dst_ext_addr[8];

    /* Source addressing */
    uint8_t  src_addr_mode;
    uint16_t src_panid;
    uint16_t src_short_addr;
    uint8_t  src_ext_addr[8];

    /* Auxiliary security header (if security_enabled) */
    uint8_t  security_level;
    uint8_t  key_id_mode;
    uint32_t frame_counter;
    uint8_t  key_source[8];
    uint8_t  key_index;

    uint8_t  header_len;       /**< Total MAC header length in bytes   */
} mac_header_t;

/** Zigbee NWK header */
typedef struct {
    uint16_t frame_control;
    uint8_t  frame_type;       /**< NWK frame type                     */
    uint8_t  protocol_version; /**< Zigbee protocol version            */
    uint8_t  discover_route;   /**< Route discovery setting            */
    bool     multicast;
    bool     security;
    bool     source_route;
    bool     dst_ieee_present;
    bool     src_ieee_present;

    uint16_t dst_addr;
    uint16_t src_addr;
    uint8_t  radius;
    uint8_t  seq_num;

    uint8_t  dst_ieee[8];      /**< Present if dst_ieee_present        */
    uint8_t  src_ieee[8];      /**< Present if src_ieee_present        */

    /* Security sub-header */
    uint8_t  sec_level;
    uint8_t  sec_key_id_mode;
    uint32_t sec_frame_counter;
    uint8_t  sec_key_seq_num;
    uint8_t  sec_key_source[8];

    /* NWK command (if frame_type == CMD) */
    uint8_t  nwk_cmd_id;

    uint8_t  header_len;       /**< Total NWK header length            */
} nwk_header_t;

/** Zigbee APS header */
typedef struct {
    uint8_t  frame_control;
    uint8_t  frame_type;       /**< APS frame type                     */
    uint8_t  delivery_mode;
    bool     ack_format;
    bool     security;
    bool     ack_request;
    bool     ext_header_present;

    uint8_t  dst_endpoint;
    uint16_t group_addr;       /**< If delivery_mode == GROUP           */
    uint16_t cluster_id;
    uint16_t profile_id;
    uint8_t  src_endpoint;
    uint8_t  aps_counter;

    /* APS command (if frame_type == CMD) */
    uint8_t  aps_cmd_id;

    uint8_t  header_len;       /**< Total APS header length            */
} aps_header_t;

/** ZCL header */
typedef struct {
    uint8_t  frame_control;
    uint8_t  frame_type;       /**< Global or cluster-specific         */
    bool     manufacturer_specific;
    uint8_t  direction;
    bool     disable_default_rsp;
    uint16_t manufacturer_code; /**< Valid if manufacturer_specific     */
    uint8_t  seq_num;
    uint8_t  command_id;

    uint8_t  header_len;       /**< Total ZCL header length            */
} zcl_header_t;

/** Fully parsed frame across all layers */
typedef struct {
    /* Raw frame data */
    uint8_t  raw[128];
    uint8_t  raw_len;

    /* Parsed layers — valid flags */
    bool     mac_valid;
    bool     nwk_valid;
    bool     aps_valid;
    bool     zcl_valid;

    mac_header_t mac;
    nwk_header_t nwk;
    aps_header_t aps;
    zcl_header_t zcl;

    /* Pointers into raw[] for payload at each layer */
    uint8_t *mac_payload;
    uint8_t  mac_payload_len;
    uint8_t *nwk_payload;
    uint8_t  nwk_payload_len;
    uint8_t *aps_payload;
    uint8_t  aps_payload_len;
    uint8_t *zcl_payload;
    uint8_t  zcl_payload_len;
} parsed_frame_t;

/* ── API ──────────────────────────────────────────────────────────── */

/**
 * @brief Parse a raw 802.15.4 frame into all available layers.
 *
 * Attempts to decode MAC, NWK, APS, and ZCL headers in order.
 * Parsing stops at the first layer that fails (e.g. encrypted NWK
 * payload will prevent APS/ZCL parsing).
 *
 * @param[in]  data   Raw frame bytes (without FCS).
 * @param[in]  len    Length of data.
 * @param[out] frame  Output parsed frame structure.
 * @return ESP_OK if at least the MAC layer was parsed successfully.
 */
esp_err_t frame_parse(const uint8_t *data, uint8_t len, parsed_frame_t *frame);

/**
 * @brief Parse only the MAC header.
 *
 * @param[in]  data   Raw frame bytes.
 * @param[in]  len    Frame length.
 * @param[out] mac    Output MAC header.
 * @return ESP_OK on success.
 */
esp_err_t frame_parse_mac(const uint8_t *data, uint8_t len, mac_header_t *mac);

/**
 * @brief Parse a Zigbee NWK header from the MAC payload.
 *
 * @param[in]  data  NWK payload start.
 * @param[in]  len   Available bytes.
 * @param[out] nwk   Output NWK header.
 * @return ESP_OK on success.
 */
esp_err_t frame_parse_nwk(const uint8_t *data, uint8_t len, nwk_header_t *nwk);

/**
 * @brief Parse a Zigbee APS header.
 *
 * @param[in]  data  APS payload start.
 * @param[in]  len   Available bytes.
 * @param[out] aps   Output APS header.
 * @return ESP_OK on success.
 */
esp_err_t frame_parse_aps(const uint8_t *data, uint8_t len, aps_header_t *aps);

/**
 * @brief Parse a ZCL header.
 *
 * @param[in]  data  ZCL payload start.
 * @param[in]  len   Available bytes.
 * @param[out] zcl   Output ZCL header.
 * @return ESP_OK on success.
 */
esp_err_t frame_parse_zcl(const uint8_t *data, uint8_t len, zcl_header_t *zcl);

/**
 * @brief Return a human-readable string for MAC frame type.
 */
const char *frame_type_str(uint8_t frame_type);

/**
 * @brief Return a human-readable string for NWK command ID.
 */
const char *nwk_cmd_str(uint8_t cmd_id);

/**
 * @brief Return a human-readable string for APS command ID.
 */
const char *aps_cmd_str(uint8_t cmd_id);

#ifdef __cplusplus
}
#endif

#endif /* ZIGBLADE_FRAME_PARSER_H */
