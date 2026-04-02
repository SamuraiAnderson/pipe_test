cmake_minimum_required(VERSION 3.10)
project(sprotocol C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(SPROTOCOL_BUILD_TESTS "Build sprotocol tests" ON)
option(SPROTOCOL_ENABLE_ASAN "Build with AddressSanitizer" OFF)

# 输出目录
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

set(SPROTOCOL_MBEDTLS_ARCHIVE "${CMAKE_SOURCE_DIR}/third_party/mbedtls-4.1.0.tar.bz2")
set(SPROTOCOL_MBEDTLS_SOURCE_DIR "${CMAKE_SOURCE_DIR}/third_party/mbedtls-4.1.0")

if(NOT EXISTS "${SPROTOCOL_MBEDTLS_SOURCE_DIR}/CMakeLists.txt")
    execute_process(
        COMMAND "${CMAKE_COMMAND}" -E tar xjf "${SPROTOCOL_MBEDTLS_ARCHIVE}"
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}/third_party"
        RESULT_VARIABLE SPROTOCOL_TAR_RESULT
    )
    if(NOT SPROTOCOL_TAR_RESULT EQUAL 0)
        message(FATAL_ERROR "Failed to extract mbedTLS archive: ${SPROTOCOL_MBEDTLS_ARCHIVE}")
    endif()
endif()

set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "" FORCE)
set(USE_STATIC_MBEDTLS_LIBRARY ON CACHE BOOL "" FORCE)
set(USE_SHARED_TF_PSA_CRYPTO_LIBRARY OFF CACHE BOOL "" FORCE)
set(USE_STATIC_TF_PSA_CRYPTO_LIBRARY ON CACHE BOOL "" FORCE)
add_subdirectory("${SPROTOCOL_MBEDTLS_SOURCE_DIR}" EXCLUDE_FROM_ALL)

# 静态库
add_library(sprotocol_lib STATIC
    src/sprotocol_core.c
    src/sprotocol_frame.c
    src/sprotocol_pairing.c
    src/sprotocol_crypto.c
)
set_target_properties(sprotocol_lib PROPERTIES OUTPUT_NAME sprotocol_lib)
target_include_directories(sprotocol_lib
    PUBLIC
        ${CMAKE_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_SOURCE_DIR}/src
)
target_link_libraries(sprotocol_lib PUBLIC tfpsacrypto)

if(SPROTOCOL_ENABLE_ASAN AND CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(sprotocol_lib PRIVATE -fsanitize=address -fno-omit-frame-pointer)
    target_link_options(sprotocol_lib PRIVATE -fsanitize=address)
endif()

# 测试程序
if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    if(SPROTOCOL_BUILD_TESTS)
        enable_testing()
        add_executable(sprotocol_tests
            tests/test_sprotocol.c
        )
        target_link_libraries(sprotocol_tests PRIVATE sprotocol_lib)
        target_include_directories(sprotocol_tests PRIVATE ${CMAKE_SOURCE_DIR}/include)
        if(SPROTOCOL_ENABLE_ASAN AND CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
            target_compile_options(sprotocol_tests PRIVATE -fsanitize=address -fno-omit-frame-pointer)
            target_link_options(sprotocol_tests PRIVATE -fsanitize=address)
        endif()
        add_test(NAME sprotocol_tests COMMAND sprotocol_tests)
    endif()
endif()
