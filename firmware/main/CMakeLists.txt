idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    REQUIRES
        nvs_flash
        esp_event
        driver
        esp_timer
        fatfs
        sdmmc
        led_strip
        ieee802154
        freertos
        spi_flash
        vfs
    PRIV_REQUIRES
        zigblade_hal
        zigbee
        thread
        matter
        wifi
        common
        ui
)
