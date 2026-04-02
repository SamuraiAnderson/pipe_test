cmake_minimum_required(VERSION 3.14)
project(sprotocol C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# ASAN 支持
option(ENABLE_ASAN "Enable AddressSanitizer" OFF)
if(ENABLE_ASAN)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()

# ============================================================
# mbedTLS 集成
# 优先从 third_party/ 解压包，否则用 FetchContent 拉取
# ============================================================
set(MBEDTLS_TARBALL "${CMAKE_SOURCE_DIR}/third_party/mbedtls-4.1.0.tar.bz2")
set(MBEDTLS_SRC_DIR "${CMAKE_BINARY_DIR}/mbedtls-src")

if(EXISTS "${MBEDTLS_TARBALL}" AND NOT EXISTS "${MBEDTLS_SRC_DIR}/CMakeLists.txt")
    message(STATUS "Extracting mbedTLS from ${MBEDTLS_TARBALL}")
    file(MAKE_DIRECTORY "${MBEDTLS_SRC_DIR}")
    execute_process(
        COMMAND ${CMAKE_COMMAND} -E tar xjf "${MBEDTLS_TARBALL}"
        WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
        RESULT_VARIABLE TAR_RESULT
    )
    if(NOT TAR_RESULT EQUAL 0)
        message(FATAL_ERROR "Failed to extract mbedTLS tarball")
    endif()
    # 解压后可能有顶层目录
    file(GLOB MBEDTLS_DIRS "${CMAKE_BINARY_DIR}/mbedtls-*")
    foreach(D ${MBEDTLS_DIRS})
        if(IS_DIRECTORY "${D}" AND NOT "${D}" STREQUAL "${MBEDTLS_SRC_DIR}")
            file(RENAME "${D}" "${MBEDTLS_SRC_DIR}")
            break()
        endif()
    endforeach()
endif()

if(EXISTS "${MBEDTLS_SRC_DIR}/CMakeLists.txt")
    message(STATUS "Using local mbedTLS source at ${MBEDTLS_SRC_DIR}")
    set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
    set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
    set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
    add_subdirectory("${MBEDTLS_SRC_DIR}" "${CMAKE_BINARY_DIR}/mbedtls-build" EXCLUDE_FROM_ALL)
    set(MBEDTLS_FOUND TRUE)
else()
    message(STATUS "mbedTLS tarball not found, fetching from GitHub...")
    include(FetchContent)
    FetchContent_Declare(
        mbedtls
        GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls.git
        GIT_TAG        v3.6.2
        GIT_SHALLOW    TRUE
    )
    set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
    set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
    set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(mbedtls)
    set(MBEDTLS_FOUND TRUE)
endif()

# ============================================================
# 协议库
# ============================================================
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/src)

add_library(sprotocol_lib STATIC
    src/sprotocol.c
    src/sprotocol_crypto.c
)
set_target_properties(sprotocol_lib PROPERTIES OUTPUT_NAME sprotocol_lib)

target_compile_options(sprotocol_lib PRIVATE -Wall -Wextra -g)

# mbedTLS 头文件和链接
if(MBEDTLS_FOUND)
    # mbedTLS 4.x 的 PSA crypto 目标为 tfpsacrypto；3.x 为 mbedcrypto
    if(TARGET tfpsacrypto)
        target_link_libraries(sprotocol_lib PUBLIC tfpsacrypto)
        target_include_directories(sprotocol_lib PUBLIC
            "${MBEDTLS_SRC_DIR}/tf-psa-crypto/include"
            "${MBEDTLS_SRC_DIR}/include")
    elseif(TARGET MbedTLS::mbedcrypto)
        target_link_libraries(sprotocol_lib PUBLIC MbedTLS::mbedcrypto)
        target_include_directories(sprotocol_lib PUBLIC "${MBEDTLS_SRC_DIR}/include")
    elseif(TARGET mbedcrypto)
        target_link_libraries(sprotocol_lib PUBLIC mbedcrypto)
        target_include_directories(sprotocol_lib PUBLIC "${MBEDTLS_SRC_DIR}/include")
    endif()
endif()

# ============================================================
# 测试程序
# ============================================================
add_executable(test_sprotocol tests/test_main.c)
target_compile_options(test_sprotocol PRIVATE -Wall -Wextra -g)
target_link_libraries(test_sprotocol PRIVATE sprotocol_lib)
