#include "web_ui.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "esp_event.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"

static const char *TAG = "web_ui";

typedef struct {
    app_state_t *state;
    web_ui_control_cb_t control_cb;
    void *control_ctx;
    httpd_handle_t server;
    bool wifi_ready;
} web_ui_ctx_t;

static web_ui_ctx_t s_web;

static const char *INDEX_HTML =
    "<!doctype html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>ZigBlade T-Embed</title><style>"
    "body{font-family:monospace;background:#08111c;color:#ecf1ff;margin:0;padding:16px}"
    ".grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px}"
    ".card{background:#132133;border:1px solid #1e3550;border-radius:12px;padding:14px}"
    "button{background:#00c6ff;border:0;border-radius:8px;padding:10px 14px;margin:4px;color:#08111c;font-weight:700}"
    "pre{max-height:260px;overflow:auto;background:#08111c;padding:10px;border-radius:8px}"
    "</style></head><body><h2>ZigBlade T-Embed Dashboard</h2><div class='grid'>"
    "<div class='card'><h3>Status</h3><pre id='state'></pre></div>"
    "<div class='card'><h3>Controls</h3>"
    "<button onclick=\"ctl('scan_start')\">Scan Start</button>"
    "<button onclick=\"ctl('scan_stop')\">Scan Stop</button>"
    "<button onclick=\"ctl('sniff_start')\">Sniffer Start</button>"
    "<button onclick=\"ctl('sniff_stop')\">Sniffer Stop</button>"
    "<button onclick=\"ctl('attack_start')\">Attack Start</button></div>"
    "<div class='card'><h3>Packets</h3><pre id='packets'></pre></div>"
    "<div class='card'><h3>Captured Keys</h3><pre id='keys'></pre></div></div>"
    "<script>let seq=0; async function refresh(){"
    "const s=await fetch('/api/state').then(r=>r.json()); document.getElementById('state').textContent=JSON.stringify(s,null,2);"
    "const p=await fetch('/api/packets?since='+seq).then(r=>r.json()); if(p.items.length){seq=p.items[p.items.length-1].seq;}"
    "document.getElementById('packets').textContent=p.items.map(x=>JSON.stringify(x)).join('\\n');"
    "const k=await fetch('/api/keys').then(r=>r.json()); document.getElementById('keys').textContent=JSON.stringify(k,null,2);"
    "} async function ctl(a){const r=await fetch('/api/control?action='+a); alert(await r.text()); refresh();}"
    "setInterval(refresh,1000); refresh();</script></body></html>";

static esp_err_t send_json(httpd_req_t *req, const char *json)
{
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    return httpd_resp_sendstr(req, json);
}

static esp_err_t root_get(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");
    return httpd_resp_sendstr(req, INDEX_HTML);
}

static esp_err_t state_get(httpd_req_t *req)
{
    char json[3072];
    int off = 0;
    off += snprintf(json + off, sizeof(json) - (size_t)off,
                    "{\"screen\":%u,\"menu\":%u,\"channel\":%u,\"state\":%u,"
                    "\"packets\":%lu,\"networks\":[",
                    (unsigned)s_web.state->screen,
                    (unsigned)s_web.state->menu_index,
                    (unsigned)s_web.state->current_channel,
                    (unsigned)s_web.state->h2_state,
                    (unsigned long)s_web.state->total_packets);
    for (size_t i = 0; i < s_web.state->network_count && off < (int)sizeof(json) - 64; i++) {
        const zb_network_info_t *n = &s_web.state->networks[i];
        off += snprintf(json + off, sizeof(json) - (size_t)off,
                        "%s{\"pan\":\"0x%04X\",\"channel\":%u,\"rssi\":%d}",
                        (i == 0) ? "" : ",",
                        n->pan_id, n->channel, n->rssi);
    }
    snprintf(json + off, sizeof(json) - (size_t)off, "],\"status\":\"%s\"}", s_web.state->status_line);
    return send_json(req, json);
}

static esp_err_t packets_get(httpd_req_t *req)
{
    char query[64] = { 0 };
    uint32_t since = 0;
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK) {
        char value[16];
        if (httpd_query_key_value(query, "since", value, sizeof(value)) == ESP_OK) {
            since = (uint32_t)strtoul(value, NULL, 10);
        }
    }

    char json[4096];
    int off = snprintf(json, sizeof(json), "{\"items\":[");
    bool first = true;
    for (size_t i = 0; i < s_web.state->packet_count && off < (int)sizeof(json) - 96; i++) {
        size_t idx = (s_web.state->packet_head + APP_MAX_PACKET_LOG - s_web.state->packet_count + i) % APP_MAX_PACKET_LOG;
        const zb_packet_info_t *pkt = &s_web.state->packets[idx];
        if (pkt->sequence <= since) {
            continue;
        }
        off += snprintf(json + off, sizeof(json) - (size_t)off,
                        "%s{\"seq\":%lu,\"ch\":%u,\"rssi\":%d,\"len\":%u}",
                        first ? "" : ",",
                        (unsigned long)pkt->sequence,
                        pkt->channel,
                        pkt->rssi,
                        (unsigned)pkt->len);
        first = false;
    }
    snprintf(json + off, sizeof(json) - (size_t)off, "]}");
    return send_json(req, json);
}

static esp_err_t keys_get(httpd_req_t *req)
{
    char json[1024];
    int off = snprintf(json, sizeof(json), "{\"items\":[");
    for (size_t i = 0; i < s_web.state->key_count && off < (int)sizeof(json) - 64; i++) {
        char hex[33];
        for (size_t j = 0; j < 16; j++) {
            snprintf(&hex[j * 2], 3, "%02X", s_web.state->keys[i].key[j]);
        }
        off += snprintf(json + off, sizeof(json) - (size_t)off,
                        "%s{\"seq\":%lu,\"key\":\"%s\"}",
                        (i == 0) ? "" : ",",
                        (unsigned long)s_web.state->keys[i].sequence,
                        hex);
    }
    snprintf(json + off, sizeof(json) - (size_t)off, "]}");
    return send_json(req, json);
}

static esp_err_t control_get(httpd_req_t *req)
{
    char query[96] = { 0 };
    char action[32] = { 0 };

    if (httpd_req_get_url_query_str(req, query, sizeof(query)) != ESP_OK ||
        httpd_query_key_value(query, "action", action, sizeof(action)) != ESP_OK) {
        httpd_resp_set_status(req, "400 Bad Request");
        return httpd_resp_sendstr(req, "{\"error\":\"missing action\"}");
    }

    esp_err_t err = s_web.control_cb ? s_web.control_cb(action, NULL, s_web.control_ctx) : ESP_ERR_NOT_SUPPORTED;
    if (err == ESP_ERR_NOT_SUPPORTED) {
        httpd_resp_set_status(req, "403 Forbidden");
        return httpd_resp_sendstr(req, "{\"error\":\"disabled in safe build\"}");
    }
    if (err != ESP_OK) {
        httpd_resp_set_status(req, "500 Internal Server Error");
        return httpd_resp_sendstr(req, "{\"error\":\"action failed\"}");
    }
    return httpd_resp_sendstr(req, "{\"ok\":true}");
}

static esp_err_t start_wifi_ap(void)
{
    if (!s_web.wifi_ready) {
        esp_netif_create_default_wifi_ap();
        wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
        ESP_ERROR_CHECK(esp_wifi_init(&cfg));
        s_web.wifi_ready = true;
    }

    wifi_config_t ap_cfg = {
        .ap = {
            .ssid = "ZigBlade-TEmbed",
            .ssid_len = 16,
            .channel = 6,
            .password = "zigblade123",
            .max_connection = 4,
            .authmode = WIFI_AUTH_WPA2_PSK,
        },
    };

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_cfg));
    ESP_ERROR_CHECK(esp_wifi_start());
    return ESP_OK;
}

esp_err_t web_ui_start(app_state_t *state, web_ui_control_cb_t control_cb, void *control_ctx)
{
    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();

    memset(&s_web, 0, sizeof(s_web));
    s_web.state = state;
    s_web.control_cb = control_cb;
    s_web.control_ctx = control_ctx;

    ESP_ERROR_CHECK(start_wifi_ap());
    ESP_ERROR_CHECK(httpd_start(&s_web.server, &cfg));

    httpd_uri_t root = { .uri = "/", .method = HTTP_GET, .handler = root_get };
    httpd_uri_t state_uri = { .uri = "/api/state", .method = HTTP_GET, .handler = state_get };
    httpd_uri_t packets_uri = { .uri = "/api/packets", .method = HTTP_GET, .handler = packets_get };
    httpd_uri_t keys_uri = { .uri = "/api/keys", .method = HTTP_GET, .handler = keys_get };
    httpd_uri_t ctl_uri = { .uri = "/api/control", .method = HTTP_GET, .handler = control_get };

    ESP_ERROR_CHECK(httpd_register_uri_handler(s_web.server, &root));
    ESP_ERROR_CHECK(httpd_register_uri_handler(s_web.server, &state_uri));
    ESP_ERROR_CHECK(httpd_register_uri_handler(s_web.server, &packets_uri));
    ESP_ERROR_CHECK(httpd_register_uri_handler(s_web.server, &keys_uri));
    ESP_ERROR_CHECK(httpd_register_uri_handler(s_web.server, &ctl_uri));
    ESP_LOGI(TAG, "Web UI started at http://192.168.4.1");
    return ESP_OK;
}

void web_ui_stop(void)
{
    if (s_web.server != NULL) {
        httpd_stop(s_web.server);
        s_web.server = NULL;
    }
    esp_wifi_stop();
}

bool web_ui_is_running(void)
{
    return s_web.server != NULL;
}
