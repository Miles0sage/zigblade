/**
 * @file pcap_writer.c
 * @brief PCAP file writer — standard libpcap format for IEEE 802.15.4.
 */

#include "pcap_writer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "esp_log.h"

static const char *TAG = "pcap_writer";

/* ── PCAP format constants ────────────────────────────────────────── */

#define PCAP_MAGIC          0xA1B2C3D4
#define PCAP_VERSION_MAJOR  2
#define PCAP_VERSION_MINOR  4
#define PCAP_SNAPLEN        256
#define PCAP_LINKTYPE_IEEE802154  195  /* LINKTYPE_IEEE802_15_4 */

/** 24-byte PCAP global header */
typedef struct __attribute__((packed)) {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;       /* GMT offset (always 0)              */
    uint32_t sigfigs;        /* timestamp accuracy (always 0)      */
    uint32_t snaplen;        /* max capture length per packet      */
    uint32_t network;        /* link-layer header type             */
} pcap_global_header_t;

/** 16-byte PCAP per-packet header */
typedef struct __attribute__((packed)) {
    uint32_t ts_sec;         /* timestamp seconds                  */
    uint32_t ts_usec;        /* timestamp microseconds             */
    uint32_t incl_len;       /* bytes of packet saved in file      */
    uint32_t orig_len;       /* actual packet length on wire       */
} pcap_packet_header_t;

/** Internal handle structure */
struct pcap_handle {
    FILE     *fp;
    uint32_t  packet_count;
    char      filename[128];
};

/* ── API implementation ───────────────────────────────────────────── */

esp_err_t pcap_open(const char *filename, pcap_handle_t *handle)
{
    if (filename == NULL || handle == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    struct pcap_handle *h = calloc(1, sizeof(struct pcap_handle));
    if (h == NULL) {
        ESP_LOGE(TAG, "Out of memory");
        return ESP_ERR_NO_MEM;
    }

    h->fp = fopen(filename, "wb");
    if (h->fp == NULL) {
        ESP_LOGE(TAG, "Failed to open %s for writing", filename);
        free(h);
        return ESP_ERR_NOT_FOUND;
    }

    strncpy(h->filename, filename, sizeof(h->filename) - 1);

    /* Write global header */
    pcap_global_header_t ghdr = {
        .magic_number  = PCAP_MAGIC,
        .version_major = PCAP_VERSION_MAJOR,
        .version_minor = PCAP_VERSION_MINOR,
        .thiszone      = 0,
        .sigfigs       = 0,
        .snaplen       = PCAP_SNAPLEN,
        .network       = PCAP_LINKTYPE_IEEE802154,
    };

    size_t written = fwrite(&ghdr, 1, sizeof(ghdr), h->fp);
    if (written != sizeof(ghdr)) {
        ESP_LOGE(TAG, "Failed to write PCAP global header");
        fclose(h->fp);
        free(h);
        return ESP_FAIL;
    }

    fflush(h->fp);
    h->packet_count = 0;

    *handle = h;
    ESP_LOGI(TAG, "PCAP opened: %s", filename);
    return ESP_OK;
}

esp_err_t pcap_write_packet(pcap_handle_t handle,
                            const uint8_t *data,
                            uint16_t len,
                            uint32_t timestamp_us)
{
    if (handle == NULL || data == NULL || len == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    if (handle->fp == NULL) {
        return ESP_ERR_INVALID_STATE;
    }

    /* Clamp to snaplen */
    uint32_t incl_len = len;
    if (incl_len > PCAP_SNAPLEN) {
        incl_len = PCAP_SNAPLEN;
    }

    pcap_packet_header_t phdr = {
        .ts_sec   = timestamp_us / 1000000,
        .ts_usec  = timestamp_us % 1000000,
        .incl_len = incl_len,
        .orig_len = len,
    };

    size_t written = fwrite(&phdr, 1, sizeof(phdr), handle->fp);
    if (written != sizeof(phdr)) {
        ESP_LOGE(TAG, "Failed to write packet header");
        return ESP_FAIL;
    }

    written = fwrite(data, 1, incl_len, handle->fp);
    if (written != incl_len) {
        ESP_LOGE(TAG, "Failed to write packet data");
        return ESP_FAIL;
    }

    /* Flush every 10 packets to limit data loss on crash */
    handle->packet_count++;
    if ((handle->packet_count % 10) == 0) {
        fflush(handle->fp);
    }

    return ESP_OK;
}

esp_err_t pcap_close(pcap_handle_t handle)
{
    if (handle == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    if (handle->fp != NULL) {
        fflush(handle->fp);
        fclose(handle->fp);
        handle->fp = NULL;
    }

    ESP_LOGI(TAG, "PCAP closed: %s (%"PRIu32" packets)",
             handle->filename, handle->packet_count);

    free(handle);
    return ESP_OK;
}

uint32_t pcap_get_packet_count(pcap_handle_t handle)
{
    if (handle == NULL) {
        return 0;
    }
    return handle->packet_count;
}
