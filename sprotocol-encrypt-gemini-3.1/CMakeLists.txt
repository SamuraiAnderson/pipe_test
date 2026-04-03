cmake_minimum_required(VERSION 3.10)
project(sprotocol C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Enable AddressSanitizer
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -g -O0 -Wall -Wextra")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")

# 输出目录
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# mbedTLS
set(ENABLE_TESTING OFF CACHE BOOL "Disable mbedTLS testing" FORCE)
set(ENABLE_PROGRAMS OFF CACHE BOOL "Disable mbedTLS programs" FORCE)
add_subdirectory(third_party/mbedtls-4.1.0)

# 包含目录
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/third_party/mbedtls-4.1.0/include
    ${CMAKE_SOURCE_DIR}/third_party/mbedtls-4.1.0/tf-psa-crypto/include
    ${CMAKE_SOURCE_DIR}/third_party/mbedtls-4.1.0/tf-psa-crypto/drivers/builtin/include
)

# 静态库
add_library(sprotocol_lib STATIC
    src/sprotocol.c
    src/sprotocol_crc.c
    src/sprotocol_crypto.c
)
set_target_properties(sprotocol_lib PROPERTIES OUTPUT_NAME sprotocol_lib)
target_link_libraries(sprotocol_lib mbedtls tfpsacrypto)

# 测试程序
if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    add_executable(test_udp
        test/test_udp.c
        test/test_main.c
    )
    target_link_libraries(test_udp sprotocol_lib mbedtls tfpsacrypto)
endif()
