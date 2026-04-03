/**
 * @file test_pairing.c
 * @brief 配对管理测试
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "sprotocol.h"
#include "udp_link.h"

#define TEST_ASSERT(cond) do { \
    if (!(cond)) { \
        printf("FAIL: %s at %s:%d\n", #cond, __FILE__, __LINE__); \
        return -1; \
    } \
} while(0)

/* 全局变量 */
static udp_link_t* g_master_link = NULL;
static udp_link_t* g_slave1_link = NULL;
static sprotocol_handle_t g_master_handle = NULL;
static sprotocol_handle_t g_slave_handle = NULL;
static int g_pair_status_changed = 0;
static uint8_t g_paired_addr = 0;
static uint8_t g_paired_status = 0;

/* 模拟时间 */
static uint32_t g_mock_time = 0;
static uint32_t get_time_cb(void) {
    return g_mock_time;
}

static void advance_time(uint32_t ms) {
    g_mock_time += ms;
}

/* 回调函数 */
static void master_send_cb(const uint8_t* data, size_t len, void* user_data) {
    (void)user_data;
    (void)data;
    udp_link_send(g_master_link, data, len, "127.0.0.1", 9001);
}

static void slave_send_cb(const uint8_t* data, size_t len, void* user_data) {
    (void)user_data;
    (void)data;
    udp_link_send(g_slave1_link, data, len, "127.0.0.1", 9000);
}

static void pair_cb(uint8_t addr, uint8_t status, void* user_data) {
    (void)user_data;
    g_pair_status_changed = 1;
    g_paired_addr = addr;
    g_paired_status = status;
}

static void online_cb(uint8_t addr, uint8_t online, void* user_data) {
    (void)user_data;
    (void)addr;
    (void)online;
}

/* 模拟接收处理 */
static void poll_and_process(sprotocol_handle_t handle, udp_link_t* link) {
    uint8_t buffer[512];
    char from_ip[32];
    uint16_t from_port;
    
    int len = udp_link_recv(link, buffer, sizeof(buffer), from_ip, sizeof(from_ip), &from_port, 1);
    if (len > 0) {
        sprotocol_input(handle, buffer, len);
    }
    sprotocol_poll(handle);
    advance_time(10);
}

int test_init(void) {
    printf("Initializing test environment...\n");
    
    g_mock_time = 0;
    
    g_master_link = udp_link_create("127.0.0.1", 9000);
    g_slave1_link = udp_link_create("127.0.0.1", 9001);
    
    TEST_ASSERT(g_master_link != NULL);
    TEST_ASSERT(g_slave1_link != NULL);
    
    sprotocol_config_t master_config;
    memset(&master_config, 0, sizeof(master_config));
    master_config.role = SPROTOCOL_ROLE_MASTER;
    master_config.local_addr = SPROTOCOL_ADDR_MASTER;
    master_config.max_slaves = SPROTOCOL_MAX_SLAVES;
    master_config.heartbeat_timeout = 3000;
    master_config.pair_timeout = 5000;
    master_config.send_cb = master_send_cb;
    master_config.pair_cb = pair_cb;
    master_config.online_cb = online_cb;
    master_config.get_time = get_time_cb;
    
    g_master_handle = sprotocol_init(&master_config);
    TEST_ASSERT(g_master_handle != NULL);
    
    sprotocol_config_t slave_config;
    memset(&slave_config, 0, sizeof(slave_config));
    slave_config.role = SPROTOCOL_ROLE_SLAVE;
    slave_config.local_addr = 0x10;
    slave_config.max_slaves = 1;
    slave_config.heartbeat_timeout = 3000;
    slave_config.pair_timeout = 5000;
    slave_config.send_cb = slave_send_cb;
    slave_config.pair_cb = pair_cb;
    slave_config.online_cb = online_cb;
    slave_config.get_time = get_time_cb;
    
    g_slave_handle = sprotocol_init(&slave_config);
    TEST_ASSERT(g_slave_handle != NULL);
    
    printf("Test environment initialized.\n");
    return 0;
}

void test_cleanup(void) {
    if (g_master_handle) {
        sprotocol_deinit(g_master_handle);
        g_master_handle = NULL;
    }
    if (g_slave_handle) {
        sprotocol_deinit(g_slave_handle);
        g_slave_handle = NULL;
    }
    if (g_master_link) {
        udp_link_destroy(g_master_link);
        g_master_link = NULL;
    }
    if (g_slave1_link) {
        udp_link_destroy(g_slave1_link);
        g_slave1_link = NULL;
    }
}

int test_single_pairing(void) {
    printf("Testing single device pairing...\n");
    
    g_pair_status_changed = 0;
    g_paired_addr = 0;
    g_paired_status = 0;
    
    int ret = sprotocol_pair_request(g_master_handle, 0x10);
    TEST_ASSERT(ret == SPROTOCOL_OK);
    
    for (int i = 0; i < 50; i++) {
        poll_and_process(g_master_handle, g_master_link);
        poll_and_process(g_slave_handle, g_slave1_link);
        usleep(5000);
    }
    
    const sprotocol_device_t* dev = sprotocol_get_device(g_master_handle, 0x10);
    TEST_ASSERT(dev != NULL);
    TEST_ASSERT(dev->pair_status == SPROTOCOL_PAIR_COMPLETE);
    
    printf("Single device pairing test passed!\n");
    return 0;
}

int test_get_paired_devices(void) {
    printf("Testing get paired devices...\n");
    
    uint8_t addrs[5];
    int count = sprotocol_get_paired_devices(g_master_handle, addrs, 5);
    TEST_ASSERT(count == 1);
    TEST_ASSERT(addrs[0] == 0x10);
    
    printf("Get paired devices test passed!\n");
    return 0;
}

int test_remove_device(void) {
    printf("Testing remove device...\n");
    
    int ret = sprotocol_remove_device(g_master_handle, 0x10);
    TEST_ASSERT(ret == SPROTOCOL_OK);
    
    const sprotocol_device_t* dev = sprotocol_get_device(g_master_handle, 0x10);
    TEST_ASSERT(dev == NULL);
    
    printf("Remove device test passed!\n");
    return 0;
}

int test_invalid_slave_address(void) {
    printf("Testing invalid slave address...\n");
    
    int ret = sprotocol_pair_request(g_master_handle, 0x05);
    TEST_ASSERT(ret == SPROTOCOL_ERR_INVALID_ARG);
    
    ret = sprotocol_pair_request(g_master_handle, 0x20);
    TEST_ASSERT(ret == SPROTOCOL_ERR_INVALID_ARG);
    
    printf("Invalid slave address test passed!\n");
    return 0;
}

int test_pair_timeout(void) {
    printf("Testing pair timeout...\n");
    
    sprotocol_deinit(g_slave_handle);
    udp_link_destroy(g_slave1_link);
    g_slave_handle = NULL;
    g_slave1_link = NULL;
    
    int ret = sprotocol_pair_request(g_master_handle, 0x11);
    TEST_ASSERT(ret == SPROTOCOL_OK);
    
    const sprotocol_device_t* dev = sprotocol_get_device(g_master_handle, 0x11);
    TEST_ASSERT(dev != NULL);
    TEST_ASSERT(dev->pair_status == SPROTOCOL_PAIR_PENDING);
    
    for (int i = 0; i < 600; i++) {
        sprotocol_poll(g_master_handle);
        advance_time(10);
    }
    
    dev = sprotocol_get_device(g_master_handle, 0x11);
    if (dev != NULL) {
        TEST_ASSERT(dev->pair_status == SPROTOCOL_PAIR_NONE);
    }
    
    sprotocol_remove_device(g_master_handle, 0x11);
    
    g_slave1_link = udp_link_create("127.0.0.1", 9001);
    TEST_ASSERT(g_slave1_link != NULL);
    
    sprotocol_config_t slave_config;
    memset(&slave_config, 0, sizeof(slave_config));
    slave_config.role = SPROTOCOL_ROLE_SLAVE;
    slave_config.local_addr = 0x10;
    slave_config.max_slaves = 1;
    slave_config.heartbeat_timeout = 3000;
    slave_config.pair_timeout = 5000;
    slave_config.send_cb = slave_send_cb;
    slave_config.pair_cb = pair_cb;
    slave_config.online_cb = online_cb;
    slave_config.get_time = get_time_cb;
    
    g_slave_handle = sprotocol_init(&slave_config);
    TEST_ASSERT(g_slave_handle != NULL);
    
    printf("Pair timeout test passed!\n");
    return 0;
}

int run_pairing_tests(void) {
    printf("\n=== Pairing Tests ===\n");
    
    if (test_init() < 0) {
        test_cleanup();
        return -1;
    }
    
    if (test_single_pairing() < 0) {
        test_cleanup();
        return -1;
    }
    
    if (test_get_paired_devices() < 0) {
        test_cleanup();
        return -1;
    }
    
    if (test_remove_device() < 0) {
        test_cleanup();
        return -1;
    }
    
    if (test_invalid_slave_address() < 0) {
        test_cleanup();
        return -1;
    }
    
    if (test_pair_timeout() < 0) {
        test_cleanup();
        return -1;
    }
    
    test_cleanup();
    printf("All pairing tests passed!\n");
    return 0;
}
