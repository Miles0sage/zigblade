idf_component_register(
    SRCS "frame_parser.c"
         "pcap_writer.c"
         "crypto.c"
    INCLUDE_DIRS "."
    REQUIRES esp_common log mbedtls
)
