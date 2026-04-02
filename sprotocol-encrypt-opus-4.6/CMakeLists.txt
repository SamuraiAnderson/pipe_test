cmake_minimum_required(VERSION 3.10)
project(sprotocol C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# ASAN support for debug builds
option(ENABLE_ASAN "Enable AddressSanitizer" OFF)
if(ENABLE_ASAN)
    add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address)
endif()

# mbedTLS integration - disable programs and tests
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
set(USE_STATIC_MBEDTLS_LIBRARY ON CACHE BOOL "" FORCE)
set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "" FORCE)

add_subdirectory(third_party/mbedtls-4.1.0)

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/src)

# sprotocol static library
add_library(sprotocol_lib STATIC
    src/sprotocol.c
    src/sprotocol_frame.c
    src/sprotocol_pair.c
    src/sprotocol_crypto.c
)
set_target_properties(sprotocol_lib PROPERTIES OUTPUT_NAME sprotocol)

target_include_directories(sprotocol_lib PRIVATE
    ${CMAKE_SOURCE_DIR}/third_party/mbedtls-4.1.0/include
    ${CMAKE_SOURCE_DIR}/third_party/mbedtls-4.1.0/tf-psa-crypto/include
    ${CMAKE_SOURCE_DIR}/third_party/mbedtls-4.1.0/tf-psa-crypto/drivers/builtin/include
)

target_link_libraries(sprotocol_lib PRIVATE tfpsacrypto)

# Test executable
if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    add_executable(test_sprotocol tests/test_main.c)
    target_link_libraries(test_sprotocol PRIVATE sprotocol_lib tfpsacrypto)
    target_include_directories(test_sprotocol PRIVATE
        ${CMAKE_SOURCE_DIR}/third_party/mbedtls-4.1.0/include
        ${CMAKE_SOURCE_DIR}/third_party/mbedtls-4.1.0/tf-psa-crypto/include
        ${CMAKE_SOURCE_DIR}/third_party/mbedtls-4.1.0/tf-psa-crypto/drivers/builtin/include
    )
endif()
