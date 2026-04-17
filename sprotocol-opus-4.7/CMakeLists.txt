cmake_minimum_required(VERSION 3.10)
project(sprotocol C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# 输出目录
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# ASAN 开关
option(SPROTOCOL_ASAN "Build with AddressSanitizer + UBSan" OFF)
if(SPROTOCOL_ASAN)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1)
    add_link_options(-fsanitize=address,undefined)
endif()

# ---------------------------------------------------------------------------
# 解压并集成 mbedTLS 4.1.0
# ---------------------------------------------------------------------------
set(MBEDTLS_TARBALL ${CMAKE_SOURCE_DIR}/third_party/mbedtls-4.1.0.tar.bz2)
set(MBEDTLS_DEPS_DIR ${CMAKE_BINARY_DIR}/_deps)
set(MBEDTLS_SRC_DIR ${MBEDTLS_DEPS_DIR}/mbedtls-4.1.0)

if(NOT EXISTS ${MBEDTLS_SRC_DIR}/CMakeLists.txt)
    message(STATUS "Extracting mbedTLS 4.1.0 ...")
    file(MAKE_DIRECTORY ${MBEDTLS_DEPS_DIR})
    execute_process(
        COMMAND ${CMAKE_COMMAND} -E tar xjf ${MBEDTLS_TARBALL}
        WORKING_DIRECTORY ${MBEDTLS_DEPS_DIR}
        RESULT_VARIABLE _mbedtls_extract_rc)
    if(NOT _mbedtls_extract_rc EQUAL 0)
        message(FATAL_ERROR "Failed to extract ${MBEDTLS_TARBALL}")
    endif()
endif()

# mbedTLS 子项目选项
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING  OFF CACHE BOOL "" FORCE)
set(USE_STATIC_MBEDTLS_LIBRARY ON  CACHE BOOL "" FORCE)
set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "" FORCE)
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
set(GEN_FILES OFF CACHE BOOL "" FORCE)
set(DISABLE_PACKAGE_CONFIG_AND_INSTALL ON CACHE BOOL "" FORCE)

add_subdirectory(${MBEDTLS_SRC_DIR} ${CMAKE_BINARY_DIR}/mbedtls_build EXCLUDE_FROM_ALL)

# ---------------------------------------------------------------------------
# sprotocol 静态库
# ---------------------------------------------------------------------------
add_library(sprotocol_lib STATIC
    src/sprotocol.c
    src/sprotocol_crypto.c
)
set_target_properties(sprotocol_lib PROPERTIES OUTPUT_NAME sprotocol)
target_include_directories(sprotocol_lib
    PUBLIC  ${CMAKE_SOURCE_DIR}/include
    PRIVATE ${CMAKE_SOURCE_DIR}/src
)
target_compile_options(sprotocol_lib PRIVATE -Wall -Wextra -Wno-unused-parameter)
# tfpsacrypto 是 mbedTLS 4.x 中提供 PSA Crypto API 的目标
target_link_libraries(sprotocol_lib PUBLIC tfpsacrypto)

# ---------------------------------------------------------------------------
# 测试程序
# ---------------------------------------------------------------------------
if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    find_package(Threads REQUIRED)
    add_executable(sprotocol_test
        test/test_main.c
        test/udp_link.c
    )
    target_include_directories(sprotocol_test PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/test
    )
    target_compile_options(sprotocol_test PRIVATE -Wall -Wextra -Wno-unused-parameter)
    target_link_libraries(sprotocol_test PRIVATE sprotocol_lib Threads::Threads)
endif()
