cmake_minimum_required(VERSION 3.10)
project(sprotocol C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# 输出目录
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# 包含目录
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/src)

# 静态库
add_library(sprotocol_lib STATIC
    src/frame.c
    src/core.c
    src/device.c
    src/pairing.c
    src/heartbeat.c
    src/blacklist.c
    src/seq.c
    src/comm.c
    src/crypto.c
)

set_target_properties(sprotocol_lib PROPERTIES OUTPUT_NAME sprotocol)

# 编译选项
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(sprotocol_lib PRIVATE -Wall -Wextra -O2)
endif()

# 可选：启用AddressSanitizer
option(ENABLE_ASAN "Enable AddressSanitizer" OFF)
if(ENABLE_ASAN)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(sprotocol_lib PRIVATE -fsanitize=address -g)
        target_link_options(sprotocol_lib PRIVATE -fsanitize=address)
    endif()
endif()

# 测试程序
if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    enable_testing()
    
    # 测试可执行文件
    add_executable(test_sprotocol
        tests/main.c
        tests/test_pairing.c
        tests/test_comm.c
        tests/test_frame.c
        tests/test_crypto.c
        tests/udp_link.c
    )
    
    target_link_libraries(test_sprotocol sprotocol_lib)
    
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(test_sprotocol PRIVATE -Wall -Wextra -O2)
    endif()
    
    if(ENABLE_ASAN)
        if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
            target_compile_options(test_sprotocol PRIVATE -fsanitize=address -g)
            target_link_options(test_sprotocol PRIVATE -fsanitize=address)
        endif()
    endif()
    
    add_test(NAME test_sprotocol COMMAND test_sprotocol)
endif()
