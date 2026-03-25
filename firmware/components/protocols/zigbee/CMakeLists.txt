idf_component_register(
    SRCS "zigbee_scanner.c"
         "zigbee_sniffer.c"
         "zigbee_injector.c"
         "zigbee_install_code.c"
    INCLUDE_DIRS "."
    REQUIRES zigblade_hal common freertos esp_timer
)
