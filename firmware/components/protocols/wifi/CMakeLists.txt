idf_component_register(
    SRCS "uart_bridge.c"
    INCLUDE_DIRS
        "."
    REQUIRES
        driver
        esp_timer
        freertos
    PRIV_REQUIRES
        common
        zigbee
        zigblade_hal
)
