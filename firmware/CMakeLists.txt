# ZigBlade — Zigbee/802.15.4 Security Testing Tool
# Top-level CMakeLists.txt for ESP-IDF

cmake_minimum_required(VERSION 3.16)

# Include components — list each explicitly since ESP-IDF needs flat component dirs
set(EXTRA_COMPONENT_DIRS
    "${CMAKE_CURRENT_SOURCE_DIR}/components/zigblade_hal"
    "${CMAKE_CURRENT_SOURCE_DIR}/components/protocols/common"
    "${CMAKE_CURRENT_SOURCE_DIR}/components/protocols/zigbee"
    "${CMAKE_CURRENT_SOURCE_DIR}/components/ui"
)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

project(zigblade)
