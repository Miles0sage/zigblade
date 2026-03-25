idf_component_register(
    SRCS "zigbee_scanner.c"
         "zigbee_sniffer.c"
         "zigbee_injector.c"
    INCLUDE_DIRS "."
    REQUIRES hal common freertos esp_common esp_timer log
)
