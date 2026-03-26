/**
 * @file matter_monitor.h
 * @brief Passive Matter-over-Thread session monitor and lab DeeDoS probe builder.
 */

#ifndef ZIGBLADE_MATTER_MONITOR_H
#define ZIGBLADE_MATTER_MONITOR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MATTER_MONITOR_MAX_SESSIONS 16
#define MATTER_DEEDOS_PROBE_LEN     32

typedef struct {
    bool     active;
    uint16_t session_id;
    uint32_t message_counter;
    uint16_t source_short_addr;
    uint16_t dest_short_addr;
    uint8_t  channel;
    uint32_t message_count;
    uint32_t last_seen_ms;
    bool     suspicious_deedos_pattern;
} matter_session_t;

typedef struct {
    bool     active;
    uint32_t total_packets;
    uint32_t matter_over_thread_packets;
    uint32_t active_sessions;
    uint32_t deedos_candidates;
    uint8_t  last_channel;
} matter_monitor_stats_t;

esp_err_t matter_monitor_start(void);
esp_err_t matter_monitor_stop(void);
esp_err_t matter_monitor_get_stats(matter_monitor_stats_t *stats);
size_t matter_monitor_get_sessions(matter_session_t *sessions, size_t max_sessions);
void matter_monitor_process_packet(const uint8_t *frame,
                                   uint8_t len,
                                   int8_t rssi,
                                   uint8_t channel,
                                   uint32_t timestamp_us);
esp_err_t matter_monitor_build_deedos_probe(uint8_t *buffer,
                                            size_t buffer_len,
                                            size_t *probe_len);

/* ── Active Matter attacks (Weakness 3 fix) ──────────────────────── */

/** Maximum TLV fuzzer payload length */
#define MATTER_FUZZ_MAX_LEN     96

/** ACL lockout test result */
typedef struct {
    bool     vulnerable;             /**< true if WriteAcl succeeded     */
    uint16_t target_session_id;      /**< Session tested                 */
    uint32_t probe_counter;          /**< Message counter used           */
    uint8_t  response[64];           /**< Raw response bytes             */
    uint8_t  response_len;           /**< Response length                */
} matter_acl_result_t;

/** Fuzzer test case */
typedef struct {
    uint8_t  payload[MATTER_FUZZ_MAX_LEN];
    uint8_t  payload_len;
    uint8_t  fuzz_type;              /**< 0=random, 1=boundary, 2=overflow */
    uint16_t target_session_id;
    uint32_t message_counter;
} matter_fuzz_case_t;

/**
 * @brief Test for CVE WriteAcl vulnerability (ACL lockout).
 *
 * Constructs a Matter IM WriteRequest targeting the AccessControl
 * cluster (0x001F) to write a restrictive ACL that locks out the
 * legitimate administrator.  This tests whether the device properly
 * validates WriteAcl permissions.
 *
 * @param[out] buffer      Output buffer for the probe frame.
 * @param[in]  buffer_len  Buffer capacity.
 * @param[out] probe_len   Actual probe length written.
 * @param[in]  session_id  Target session ID from monitoring.
 * @param[in]  msg_counter Message counter (should be > last seen).
 * @param[out] result      Test result (set vulnerable flag after
 *                          observing the device's response separately).
 * @return ESP_OK on success.
 */
esp_err_t matter_acl_lockout_test(uint8_t *buffer,
                                  size_t buffer_len,
                                  size_t *probe_len,
                                  uint16_t session_id,
                                  uint32_t msg_counter,
                                  matter_acl_result_t *result);

/**
 * @brief Generate a fuzzed Matter TLV message.
 *
 * Creates malformed Matter protocol messages with various fuzzing
 * strategies to test device robustness:
 *   - Type 0: Random bytes in TLV structure
 *   - Type 1: Boundary values (0, 0xFF, 0xFFFF, max lengths)
 *   - Type 2: Overflow payloads (oversized TLV lengths)
 *
 * @param[out] fuzz_case   Output fuzz case with payload.
 * @param[in]  fuzz_type   Fuzzing strategy (0, 1, or 2).
 * @param[in]  session_id  Target session ID.
 * @param[in]  msg_counter Message counter to use.
 * @param[in]  seed        Random seed for reproducibility.
 * @return ESP_OK on success.
 */
esp_err_t matter_fuzzer(matter_fuzz_case_t *fuzz_case,
                        uint8_t fuzz_type,
                        uint16_t session_id,
                        uint32_t msg_counter,
                        uint32_t seed);

#ifdef __cplusplus
}
#endif

#endif /* ZIGBLADE_MATTER_MONITOR_H */
