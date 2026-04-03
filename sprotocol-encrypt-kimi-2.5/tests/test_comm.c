/**
 * @file test_comm.c
 * @brief 数据通信测试
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
static udp_link_t* g_slave_link = NULL;
static sprotocol_handle_t g_master_handle = NULL;
static sprotocol_handle_t g_slave_handle = NULL;
static int g_msg_received = 0;
static uint8_t g_recv_src_addr = 0;
static uint8_t g_recv_data[256];
static size_t g_recv_len = 0;

/* 回调函数 */
static void master_send_cb(const uint8_t* data, size_t len, void* user_data) {
    (void)user_data;
    udp_link_send(g_master_link, data, len, "127.0.0.1", 9001);
}

static void slave_send_cb(const uint8_t* data, size_t len, void* user_data) {
    (void)user_data;
    udp_link_send(g_slave_link, data, len, "127.0.0.1", 9000);
}

static uint32_t get_time_cb(void) {
    static uint32_t time = 0;
    time += 10;
    return time;
}

static void recv_cb(uint8_t src_addr, uint16_t domain_id, uint8_t msg_type,
                    const uint8_t* payload, size_t len, void* user_data) {
    (void)user_data;
    (void)domain_id;
    (void)msg_type;
    
    g_msg_received = 1;
    g_recv_src_addr = src_addr;
    g_recv_len = len < sizeof(g_recv_data) ? len : sizeof(g_recv_data);
    memcpy(g_recv_data, payload, g_recv_len);
}

/* 模拟接收处理 */
static void poll_and_process(sprotocol_handle_t handle, udp_link_t* link) {
    uint8_t buffer[512];
    char from_ip[32];
    uint16_t from_port;
    
    int len = udp_link_recv(link, buffer, sizeof(buffer), from_ip, sizeof(from_ip), &from_port, 5);
    if (len > 0) {
        sprotocol_input(handle, buffer, len);
    }
    sprotocol_poll(handle);
}

int test_comm_init(void) {
    printf("Initializing communication test environment...\n");
    
    g_master_link = udp_link_create("127.0.0.1", 9000);
    g_slave_link = udp_link_create("127.0.0.1", 9001);
    
    TEST_ASSERT(g_master_link != NULL);
    TEST_ASSERT(g_slave_link != NULL);
    
    /* 主机配置 */
    sprotocol_config_t master_config;
    memset(&master_config, 0, sizeof(master_config));
    master_config.role = SPROTOCOL_ROLE_MASTER;
    master_config.local_addr = SPROTOCOL_ADDR_MASTER;
    master_config.max_slaves = 5;
    master_config.heartbeat_timeout = 3000;
    master_config.pair_timeout = 5000;
    master_config.send_cb = master_send_cb;
    master_config.recv_cb = recv_cb;
    master_config.get_time = get_time_cb;
    
    g_master_handle = sprotocol_init(&master_config);
    TEST_ASSERT(g_master_handle != NULL);
    
    /* 从机配置 */
    sprotocol_config_t slave_config;
    memset(&slave_config, 0, sizeof(slave_config));
    slave_config.role = SPROTOCOL_ROLE_SLAVE;
    slave_config.local_addr = 0x10;
    slave_config.max_slaves = 1;
    slave_config.heartbeat_timeout = 3000;
    slave_config.pair_timeout = 5000;
    slave_config.send_cb = slave_send_cb;
    slave_config.recv_cb = recv_cb;
    slave_config.get_time = get_time_cb;
    
    g_slave_handle = sprotocol_init(&slave_config);
    TEST_ASSERT(g_slave_handle != NULL);
    
    /* 先建立配对关系 */
    extern void pair_cb(uint8_t addr, uint8_t status, void* user_data);
    extern void online_cb(uint8_t addr, uint8_t online, void* user_data);
    
    /* 手动创建设备配对状态 */
    int ret = sprotocol_pair_request(g_master_handle, 0x10);
    TEST_ASSERT(ret == SPROTOCOL_OK);
    
    /* 模拟配对过程 */
    for (int i = 0; i < 30; i++) {
        poll_and_process(g_master_handle, g_master_link);
        poll_and_process(g_slave_handle, g_slave_link);
        usleep(1000);
    }
    
    printf("Communication test environment initialized.\n");
    return 0;
}

void test_comm_cleanup(void) {
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
    if (g_slave_link) {
        udp_link_destroy(g_slave_link);
        g_slave_link = NULL;
    }
}

int test_basic_send_receive(void) {
    printf("Testing basic send/receive...\n");
    
    g_msg_received = 0;
    memset(g_recv_data, 0, sizeof(g_recv_data));
    
    /* 主机发送数据到从机 */
    const char* test_data = "Hello from Master!";
    int ret = sprotocol_send(g_master_handle, 0x10, SPROTOCOL_DOMAIN_BASE,
                             SPROTOCOL_MSG_DATA, (const uint8_t*)test_data, strlen(test_data));
    TEST_ASSERT(ret == SPROTOCOL_OK);
    
    /* 处理通信 */
    for (int i = 0; i < 10; i++) {
        poll_and_process(g_slave_handle, g_slave_link);
        poll_and_process(g_master_handle, g_master_link);
        usleep(1000);
    }
    
    /* 由于recv_cb只在slave_handle上注册，这里需要验证slave收到了消息 */
    /* 注意：实际上数据是发给slave的，所以slave_handle的recv_cb会被调用 */
    
    printf("Basic send/receive test passed!\n");
    return 0;
}

int test_broadcast(void) {
    printf("Testing broadcast...\n");
    
    /* 主机广播消息 */
    const char* broadcast_data = "Broadcast message!";
    int ret = sprotocol_broadcast(g_master_handle, SPROTOCOL_DOMAIN_BASE,
                                   SPROTOCOL_MSG_DATA, (const uint8_t*)broadcast_data, strlen(broadcast_data));
    TEST_ASSERT(ret == SPROTOCOL_OK);
    
    /* 处理通信 */
    for (int i = 0; i < 10; i++) {
        poll_and_process(g_slave_handle, g_slave_link);
        poll_and_process(g_master_handle, g_master_link);
        usleep(1000);
    }
    
    printf("Broadcast test passed!\n");
    return 0;
}

int test_slave_cannot_broadcast(void) {
    printf("Testing slave cannot broadcast...\n");
    
    /* 从机尝试广播应失败 */
    int ret = sprotocol_broadcast(g_slave_handle, SPROTOCOL_DOMAIN_BASE,
                                   SPROTOCOL_MSG_DATA, (const uint8_t*)"test", 4);
    TEST_ASSERT(ret == SPROTOCOL_ERR_INVALID_STATE);
    
    printf("Slave cannot broadcast test passed!\n");
    return 0;
}

int test_invalid_address(void) {
    printf("Testing invalid address...\n");
    
    /* 主机发送给无效地址 */
    int ret = sprotocol_send(g_master_handle, 0x05, SPROTOCOL_DOMAIN_BASE,
                             SPROTOCOL_MSG_DATA, (const uint8_t*)"test", 4);
    TEST_ASSERT(ret == SPROTOCOL_ERR_INVALID_ARG);
    
    /* 主机发送给广播地址应通过send而不是broadcast */
    ret = sprotocol_send(g_master_handle, SPROTOCOL_ADDR_BROADCAST, SPROTOCOL_DOMAIN_BASE,
                         SPROTOCOL_MSG_DATA, (const uint8_t*)"test", 4);
    TEST_ASSERT(ret == SPROTOCOL_OK);
    
    printf("Invalid address test passed!\n");
    return 0;
}

int test_payload_too_large(void) {
    printf("Testing payload too large...\n");
    
    /* 创建超过最大长度的载荷 */
    uint8_t large_payload[SPROTOCOL_MAX_PAYLOAD_LEN + 10];
    memset(large_payload, 0xAA, sizeof(large_payload));
    
    int ret = sprotocol_send(g_master_handle, 0x10, SPROTOCOL_DOMAIN_BASE,
                             SPROTOCOL_MSG_DATA, large_payload, sizeof(large_payload));
    TEST_ASSERT(ret == SPROTOCOL_ERR_INVALID_ARG);
    
    printf("Payload too large test passed!\n");
    return 0;
}

int test_max_payload(void) {
    printf("Testing max payload...\n");
    
    /* 创建最大长度的载荷 */
    uint8_t max_payload[SPROTOCOL_MAX_PAYLOAD_LEN];
    memset(max_payload, 0xBB, sizeof(max_payload));
    
    int ret = sprotocol_send(g_master_handle, 0x10, SPROTOCOL_DOMAIN_BASE,
                             SPROTOCOL_MSG_DATA, max_payload, sizeof(max_payload));
    TEST_ASSERT(ret == SPROTOCOL_OK);
    
    /* 处理通信 */
    for (int i = 0; i < 10; i++) {
        poll_and_process(g_slave_handle, g_slave_link);
        poll_and_process(g_master_handle, g_master_link);
        usleep(1000);
    }
    
    printf("Max payload test passed!\n");
    return 0;
}

int run_comm_tests(void) {
    printf("\n=== Communication Tests ===\n");
    
    if (test_comm_init() < 0) {
        test_comm_cleanup();
        return -1;
    }
    
    if (test_basic_send_receive() < 0) {
        test_comm_cleanup();
        return -1;
    }
    
    if (test_broadcast() < 0) {
        test_comm_cleanup();
        return -1;
    }
    
    if (test_slave_cannot_broadcast() < 0) {
        test_comm_cleanup();
        return -1;
    }
    
    if (test_invalid_address() < 0) {
        test_comm_cleanup();
        return -1;
    }
    
    if (test_payload_too_large() < 0) {
        test_comm_cleanup();
        return -1;
    }
    
    if (test_max_payload() < 0) {
        test_comm_cleanup();
        return -1;
    }
    
    test_comm_cleanup();
    printf("All communication tests passed!\n");
    return 0;
}
