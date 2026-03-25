idf_component_register(
    SRCS "ieee802154_hal.c"
    INCLUDE_DIRS "."
    REQUIRES ieee802154 freertos esp_common log
)
