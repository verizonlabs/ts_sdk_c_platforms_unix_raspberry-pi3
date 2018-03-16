# Copyright (c) 2017, 2018 Verizon, Inc. All rights reserved.

file( GLOB SOURCES ${SOURCES} *.c )

add_library( ts_sdk_platforms OBJECT "" )

target_sources( ts_sdk_platforms PRIVATE ${SOURCES} )

target_include_directories( ts_sdk_platforms PRIVATE
	${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/sdk/include
    ${CMAKE_SOURCE_DIR}/sdk_dependencies/cJSON
    ${CMAKE_SOURCE_DIR}/sdk_dependencies/tinycbor/src
    ${CMAKE_SOURCE_DIR}/sdk_dependencies/mbedtls/include
    ${CMAKE_SOURCE_DIR}/sdk_dependencies/paho.mqtt.embedded-c/MQTTPacket/src
    ${CMAKE_SOURCE_DIR}/sdk_dependencies/paho.mqtt.embedded-c/MQTTClient-C/src )
