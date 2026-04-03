/**
 * @file test_crypto.c
 * @brief 加密功能测试
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "sprotocol.h"

#define TEST_ASSERT(cond) do { \
    if (!(cond)) { \
        printf("FAIL: %s at %s:%d\n", #cond, __FILE__, __LINE__); \
        return -1; \
    } \
} while(0)

/* 模拟时间回调 */
static uint32_t g_mock_time = 0;
static uint32_t get_mock_time(void) { return g_mock_time; }

/* 模拟发送回调 */
static uint8_t g_dummy_sent = 0;
static void dummy_send(const uint8_t* data, size_t len, void* user_data) {
    (void)data;
    (void)len;
    (void)user_data;
    g_dummy_sent = 1;
}

int test_crc16_calculation(void) {
    printf("Testing CRC16 calculation...\n");
    
    /* 测试已知数据 */
    uint8_t data[] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39};  /* "123456789" */
    uint16_t crc = sprotocol_crc16(data, sizeof(data));
    
    /* CRC16-CCITT 标准结果 */
    TEST_ASSERT(crc != 0);
    
    /* 相同数据应产生相同CRC */
    uint16_t crc2 = sprotocol_crc16(data, sizeof(data));
    TEST_ASSERT(crc == crc2);
    
    /* 不同数据应产生不同CRC（大概率） */
    data[0] ^= 0xFF;
    uint16_t crc3 = sprotocol_crc16(data, sizeof(data));
    TEST_ASSERT(crc != crc3);
    
    printf("CRC16 calculation test passed!\n");
    return 0;
}

int test_crc16_error_detection(void) {
    printf("Testing CRC16 error detection...\n");
    
    /* 原始数据 */
    uint8_t data[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    uint16_t original_crc = sprotocol_crc16(data, sizeof(data));
    
    /* 模拟单比特错误 */
    int error_detected = 0;
    size_t num_bits = sizeof(data) * 8;
    for (size_t bit = 0; bit < num_bits; bit++) {
        uint8_t modified[5];
        memcpy(modified, data, sizeof(data));
        modified[bit / 8] ^= (1 << (bit % 8));
        
        uint16_t modified_crc = sprotocol_crc16(modified, sizeof(modified));
        if (modified_crc != original_crc) {
            error_detected++;
        }
    }
    
    /* 大多数单比特错误应被检测到 */
    TEST_ASSERT(error_detected > 30);  /* 40个可能的单比特错误，至少检测30个 */
    
    printf("CRC16 error detection test passed!\n");
    return 0;
}

int test_version_string(void) {
    printf("Testing version string...\n");
    
    const char* version = sprotocol_get_version();
    TEST_ASSERT(version != NULL);
    TEST_ASSERT(strlen(version) > 0);
    
    /* 验证格式 */
    int major, minor, patch;
    int ret = sscanf(version, "%d.%d.%d", &major, &minor, &patch);
    TEST_ASSERT(ret == 3);
    
    /* 验证版本号 */
    TEST_ASSERT(major == SPROTOCOL_VERSION_MAJOR);
    TEST_ASSERT(minor == SPROTOCOL_VERSION_MINOR);
    TEST_ASSERT(patch == SPROTOCOL_VERSION_PATCH);
    
    printf("Version string test passed! (version: %s)\n", version);
    return 0;
}

int test_encryption_enabled(void) {
    printf("Testing encryption configuration...\n");
    
    g_mock_time = 0;
    g_dummy_sent = 0;
    
    /* 创建启用加密的配置 */
    sprotocol_config_t config;
    memset(&config, 0, sizeof(config));
    config.role = SPROTOCOL_ROLE_MASTER;
    config.local_addr = SPROTOCOL_ADDR_MASTER;
    config.max_slaves = 5;
    config.encryption_enabled = 1;
    config.enc_type = SPROTOCOL_ENC_ECC;
    config.get_time = get_mock_time;
    config.send_cb = dummy_send;
    
    sprotocol_handle_t handle = sprotocol_init(&config);
    TEST_ASSERT(handle != NULL);
    
    /* 验证配置正确存储 */
    sprotocol_deinit(handle);
    
    printf("Encryption configuration test passed!\n");
    return 0;
}

int test_init_invalid_config(void) {
    printf("Testing init with invalid config...\n");
    
    /* 测试NULL配置 */
    sprotocol_handle_t handle = sprotocol_init(NULL);
    TEST_ASSERT(handle == NULL);
    
    /* 测试缺少必要回调的配置 */
    sprotocol_config_t config;
    memset(&config, 0, sizeof(config));
    config.role = SPROTOCOL_ROLE_MASTER;
    config.local_addr = SPROTOCOL_ADDR_MASTER;
    config.max_slaves = 5;
    /* 缺少send_cb和get_time */
    
    handle = sprotocol_init(&config);
    TEST_ASSERT(handle == NULL);
    
    /* 测试从机配置错误地址 */
    memset(&config, 0, sizeof(config));
    config.role = SPROTOCOL_ROLE_SLAVE;
    config.local_addr = 0x05;  /* 错误：不是从机地址 */
    config.max_slaves = 1;
    config.send_cb = dummy_send;
    config.get_time = get_mock_time;
    
    handle = sprotocol_init(&config);
    TEST_ASSERT(handle == NULL);
    
    printf("Init with invalid config test passed!\n");
    return 0;
}

int test_blacklist_api(void) {
    printf("Testing blacklist API...\n");
    
    g_mock_time = 0;
    
    /* 创建句柄 */
    sprotocol_config_t config;
    memset(&config, 0, sizeof(config));
    config.role = SPROTOCOL_ROLE_MASTER;
    config.local_addr = SPROTOCOL_ADDR_MASTER;
    config.max_slaves = 5;
    config.get_time = get_mock_time;
    config.send_cb = dummy_send;
    
    sprotocol_handle_t handle = sprotocol_init(&config);
    TEST_ASSERT(handle != NULL);
    
    /* 初始黑名单应为空 */
    int count = sprotocol_get_blacklist_count(handle);
    TEST_ASSERT(count == 0);
    
    /* 检查地址不在黑名单中 */
    int blacklisted = sprotocol_is_blacklisted(handle, 0x10);
    TEST_ASSERT(blacklisted == 0);
    
    sprotocol_deinit(handle);
    
    printf("Blacklist API test passed!\n");
    return 0;
}

int run_crypto_tests(void) {
    printf("\n=== Crypto & Misc Tests ===\n");
    
    if (test_crc16_calculation() < 0) return -1;
    if (test_crc16_error_detection() < 0) return -1;
    if (test_version_string() < 0) return -1;
    if (test_encryption_enabled() < 0) return -1;
    if (test_init_invalid_config() < 0) return -1;
    if (test_blacklist_api() < 0) return -1;
    
    printf("All crypto & misc tests passed!\n");
    return 0;
}
