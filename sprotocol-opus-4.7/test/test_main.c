/**
 * @file test_main.c
 * @brief sprotocol 自测套件：启动 Master + 两个 Slave，在本地 UDP 上完成所有用例。
 *
 *   Master : 127.0.0.1:9000 (addr=0x00)
 *   Slave1 : 127.0.0.1:9001 (addr=0x10)
 *   Slave2 : 127.0.0.1:9002 (addr=0x11)
 */

#include "sprotocol.h"
#include "udp_link.h"

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

/* ---------- 统计 ---------- */

static int g_pass = 0;
static int g_fail = 0;

#define REPORT(name, cond)                                          \
    do {                                                            \
        if (cond) { g_pass++; printf("[PASS] %s\n", (name)); }      \
        else      { g_fail++; printf("[FAIL] %s\n", (name)); }      \
    } while (0)

/* ---------- 时间工具 ---------- */

static uint32_t now_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint32_t)(tv.tv_sec * 1000u + tv.tv_usec / 1000u);
}

static void sleep_ms(uint32_t ms)
{
    struct timespec ts = { .tv_sec = ms / 1000, .tv_nsec = (long)((ms % 1000) * 1000000L) };
    nanosleep(&ts, NULL);
}

/* ---------- Node: handle + link + 回调缓存 ---------- */

typedef struct node {
    sprotocol_handle_t h;
    udp_link_t* link;
    uint8_t local_addr;
    const char* name;

    /* 收包缓存 */
    pthread_mutex_t m;
    uint8_t last_payload[SPROTOCOL_MAX_PAYLOAD_LEN];
    size_t last_len;
    uint8_t last_src;
    uint16_t last_domain;
    uint8_t last_msg_type;
    int recv_count;

    /* 状态回调缓存 */
    int pair_events;                 /* 累积次数 */
    uint8_t last_pair_addr;
    uint8_t last_pair_status;
    int online_events;
    uint8_t last_online_addr;
    uint8_t last_online_state;
} node_t;

static void on_recv(uint8_t src, uint16_t domain, uint8_t msg_type,
                    const uint8_t* p, size_t l, void* ud)
{
    node_t* n = (node_t*)ud;
    pthread_mutex_lock(&n->m);
    n->last_src = src;
    n->last_domain = domain;
    n->last_msg_type = msg_type;
    n->last_len = l > sizeof(n->last_payload) ? sizeof(n->last_payload) : l;
    if (n->last_len) memcpy(n->last_payload, p, n->last_len);
    n->recv_count++;
    pthread_mutex_unlock(&n->m);
}

static void on_pair(uint8_t addr, uint8_t status, void* ud)
{
    node_t* n = (node_t*)ud;
    pthread_mutex_lock(&n->m);
    n->last_pair_addr = addr;
    n->last_pair_status = status;
    n->pair_events++;
    pthread_mutex_unlock(&n->m);
}

static void on_online(uint8_t addr, uint8_t online, void* ud)
{
    node_t* n = (node_t*)ud;
    pthread_mutex_lock(&n->m);
    n->last_online_addr = addr;
    n->last_online_state = online;
    n->online_events++;
    pthread_mutex_unlock(&n->m);
}

/* 发送回调 —— 桥接到 UDP */
static void on_send(const uint8_t* data, size_t len, void* ud)
{
    udp_link_send_cb(data, len, ud);
}

/* ---------- 全局 poll 线程 ---------- */

static node_t* g_nodes[8];
static int g_node_count = 0;
static atomic_int g_poll_running;
static pthread_t g_poll_thread;

static void* poll_loop(void* arg)
{
    (void)arg;
    while (atomic_load(&g_poll_running)) {
        for (int i = 0; i < g_node_count; ++i) {
            if (g_nodes[i] && g_nodes[i]->h) sprotocol_poll(g_nodes[i]->h);
        }
        sleep_ms(20);
    }
    return NULL;
}

/* ---------- Node 生命周期 ---------- */

static node_t* node_new_master(const char* name, uint8_t max_slaves,
                               uint32_t heartbeat_timeout_ms,
                               uint32_t pair_timeout_ms,
                               int encryption_enabled)
{
    node_t* n = (node_t*)calloc(1, sizeof(*n));
    n->local_addr = SPROTOCOL_ADDR_MASTER;
    n->name = name;
    pthread_mutex_init(&n->m, NULL);

    n->link = udp_link_create(n->local_addr);
    if (!n->link) { free(n); return NULL; }

    sprotocol_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = SPROTOCOL_ROLE_MASTER;
    cfg.local_addr = SPROTOCOL_ADDR_MASTER;
    cfg.max_slaves = max_slaves;
    cfg.heartbeat_timeout = heartbeat_timeout_ms;
    cfg.pair_timeout = pair_timeout_ms;
    cfg.encryption_enabled = (uint8_t)encryption_enabled;
    cfg.enc_type = encryption_enabled ? SPROTOCOL_ENC_ECC : SPROTOCOL_ENC_NONE;
    cfg.send_cb = on_send;
    cfg.pair_cb = on_pair;
    cfg.online_cb = on_online;
    cfg.recv_cb = on_recv;
    cfg.get_time = now_ms;
    cfg.user_data = n;
    extern void node_send_thunk(const uint8_t*, size_t, void*);
    cfg.send_cb = node_send_thunk;

    n->h = sprotocol_init(&cfg);
    if (!n->h) { udp_link_destroy(n->link); free(n); return NULL; }
    udp_link_attach(n->link, n->h);

    g_nodes[g_node_count++] = n;
    return n;
}

static node_t* node_new_slave(const char* name, uint8_t local_addr,
                              uint32_t heartbeat_timeout_ms,
                              uint32_t pair_timeout_ms,
                              int encryption_enabled)
{
    node_t* n = (node_t*)calloc(1, sizeof(*n));
    n->local_addr = local_addr;
    n->name = name;
    pthread_mutex_init(&n->m, NULL);

    n->link = udp_link_create(local_addr);
    if (!n->link) { free(n); return NULL; }

    sprotocol_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = SPROTOCOL_ROLE_SLAVE;
    cfg.local_addr = local_addr;
    cfg.max_slaves = 1;
    cfg.heartbeat_timeout = heartbeat_timeout_ms;
    cfg.pair_timeout = pair_timeout_ms;
    cfg.encryption_enabled = (uint8_t)encryption_enabled;
    cfg.enc_type = encryption_enabled ? SPROTOCOL_ENC_ECC : SPROTOCOL_ENC_NONE;
    cfg.pair_cb = on_pair;
    cfg.online_cb = on_online;
    cfg.recv_cb = on_recv;
    cfg.get_time = now_ms;
    cfg.user_data = n;
    extern void node_send_thunk(const uint8_t*, size_t, void*);
    cfg.send_cb = node_send_thunk;

    n->h = sprotocol_init(&cfg);
    if (!n->h) { udp_link_destroy(n->link); free(n); return NULL; }
    udp_link_attach(n->link, n->h);
    g_nodes[g_node_count++] = n;
    return n;
}

void node_send_thunk(const uint8_t* data, size_t len, void* ud)
{
    node_t* n = (node_t*)ud;
    if (!n || !n->link) return;
    udp_link_send_cb(data, len, n->link);
}

static void node_free(node_t* n)
{
    if (!n) return;
    if (n->h) sprotocol_deinit(n->h);
    if (n->link) udp_link_destroy(n->link);
    pthread_mutex_destroy(&n->m);
    free(n);
}

/* ---------- 同步辅助 ---------- */

static bool wait_until(int timeout_ms, int (*pred)(void*), void* ud)
{
    int waited = 0;
    while (!pred(ud)) {
        if (waited >= timeout_ms) return false;
        sleep_ms(10);
        waited += 10;
    }
    return true;
}

node_t* g_master;  /* 用于闭包辅助 */

/* ============================================================ */
/* 测试用例                                                     */
/* ============================================================ */

static void test_crc16(void)
{
    /* CRC-16/CCITT-FALSE 标准测试向量："123456789" → 0x29B1 */
    uint16_t c = sprotocol_crc16((const uint8_t*)"123456789", 9);
    REPORT("CRC16-CCITT known vector", c == 0x29B1);

    /* 空输入 → 0xFFFF */
    c = sprotocol_crc16((const uint8_t*)"", 0);
    REPORT("CRC16 empty input", c == 0xFFFF);
}

static void test_version(void)
{
    const char* v = sprotocol_get_version();
    REPORT("version string present", v && strlen(v) > 0);
}

static void test_invalid_init(void)
{
    /* 非法 local_addr */
    sprotocol_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = SPROTOCOL_ROLE_MASTER;
    cfg.local_addr = 0x05;              /* 非法 */
    cfg.max_slaves = 2;
    cfg.get_time = now_ms;
    REPORT("init rejects bad master addr", sprotocol_init(&cfg) == NULL);

    /* 超过 max_slaves */
    cfg.local_addr = SPROTOCOL_ADDR_MASTER;
    cfg.max_slaves = 10;
    REPORT("init rejects max_slaves=10", sprotocol_init(&cfg) == NULL);

    /* 非法 slave 地址 */
    cfg.role = SPROTOCOL_ROLE_SLAVE;
    cfg.local_addr = 0x05;
    cfg.max_slaves = 1;
    REPORT("init rejects bad slave addr", sprotocol_init(&cfg) == NULL);
}

static int pred_pair_complete_master(void* ud)
{
    node_t* m = (node_t*)ud;
    return sprotocol_is_device_online(m->h, 0x10) ? 1 : 0;
}

static int pred_pair_complete_slave(void* ud)
{
    node_t* s = (node_t*)ud;
    return sprotocol_is_device_online(s->h, SPROTOCOL_ADDR_MASTER) ? 1 : 0;
}

static void test_single_pair(node_t* master, node_t* slave1)
{
    int rc = sprotocol_pair_request(master->h, 0x10);
    REPORT("pair_request returns OK", rc == SPROTOCOL_OK);

    bool ok_m = wait_until(2000, pred_pair_complete_master, master);
    bool ok_s = wait_until(2000, pred_pair_complete_slave, slave1);
    REPORT("pair completes (master sees online)", ok_m);
    REPORT("pair completes (slave sees master online)", ok_s);

    uint8_t addrs[8];
    int n = sprotocol_get_paired_devices(master->h, addrs, 8);
    REPORT("master has 1 paired device", n == 1 && addrs[0] == 0x10);
}

static void test_multi_pair(node_t* master, node_t* slave2)
{
    (void)master;
    int rc = sprotocol_pair_request(g_master->h, 0x11);
    REPORT("pair_request to second slave", rc == SPROTOCOL_OK);

    bool ok = wait_until(2000, pred_pair_complete_slave, slave2);
    REPORT("second pair completes", ok);

    uint8_t addrs[8];
    int n = sprotocol_get_paired_devices(g_master->h, addrs, 8);
    REPORT("master has 2 paired devices", n == 2);
}

static void test_invalid_pair_addr(void)
{
    /* 超出 max_slaves 范围（master 配的 max=2 → 合法 0x10, 0x11） */
    int rc = sprotocol_pair_request(g_master->h, 0x12);
    REPORT("invalid pair addr rejected", rc == SPROTOCOL_ERR_INVALID_ARG);

    /* 太低 */
    rc = sprotocol_pair_request(g_master->h, 0x05);
    REPORT("low pair addr rejected", rc == SPROTOCOL_ERR_INVALID_ARG);
}

/* ---------- 明文数据 ---------- */

static void test_basic_data(node_t* master, node_t* slave1)
{
    pthread_mutex_lock(&slave1->m);
    slave1->recv_count = 0;
    pthread_mutex_unlock(&slave1->m);

    uint8_t msg[] = "hello-plain";
    int rc = sprotocol_send(master->h, 0x10, SPROTOCOL_DOMAIN_BASE,
                            SPROTOCOL_MSG_DATA, msg, sizeof(msg));
    REPORT("send plaintext OK", rc == SPROTOCOL_OK);

    int waited = 0;
    while (slave1->recv_count == 0 && waited < 1000) { sleep_ms(10); waited += 10; }

    pthread_mutex_lock(&slave1->m);
    int got = slave1->recv_count;
    int match = (slave1->last_len == sizeof(msg)) &&
                (memcmp(slave1->last_payload, msg, sizeof(msg)) == 0) &&
                (slave1->last_src == SPROTOCOL_ADDR_MASTER);
    pthread_mutex_unlock(&slave1->m);
    REPORT("slave received plaintext", got == 1 && match);
}

static void test_broadcast(node_t* master, node_t* slave1, node_t* slave2)
{
    pthread_mutex_lock(&slave1->m); slave1->recv_count = 0; pthread_mutex_unlock(&slave1->m);
    pthread_mutex_lock(&slave2->m); slave2->recv_count = 0; pthread_mutex_unlock(&slave2->m);

    uint8_t msg[] = "broadcast-payload";
    int rc = sprotocol_broadcast(master->h, SPROTOCOL_DOMAIN_BASE,
                                 SPROTOCOL_MSG_DATA, msg, sizeof(msg));
    REPORT("broadcast OK", rc == SPROTOCOL_OK);

    int waited = 0;
    while ((slave1->recv_count == 0 || slave2->recv_count == 0) && waited < 1000) {
        sleep_ms(10); waited += 10;
    }
    REPORT("broadcast received by slave1", slave1->recv_count > 0);
    REPORT("broadcast received by slave2", slave2->recv_count > 0);
}

/* ---------- 加密数据 ---------- */

static void test_encrypted_roundtrip(node_t* master, node_t* slave1)
{
    pthread_mutex_lock(&slave1->m); slave1->recv_count = 0; pthread_mutex_unlock(&slave1->m);
    pthread_mutex_lock(&master->m); master->recv_count = 0; pthread_mutex_unlock(&master->m);

    uint8_t msg[] = "encrypted-ping-0123456789";
    int rc = sprotocol_send(master->h, 0x10, SPROTOCOL_DOMAIN_OTA,
                            SPROTOCOL_MSG_DATA, msg, sizeof(msg));
    REPORT("encrypted send OK", rc == SPROTOCOL_OK);

    int waited = 0;
    while (slave1->recv_count == 0 && waited < 1000) { sleep_ms(10); waited += 10; }
    pthread_mutex_lock(&slave1->m);
    int ok = (slave1->last_len == sizeof(msg)) &&
             (memcmp(slave1->last_payload, msg, sizeof(msg)) == 0) &&
             (slave1->last_domain == SPROTOCOL_DOMAIN_OTA);
    pthread_mutex_unlock(&slave1->m);
    REPORT("slave decrypted master plaintext", ok);

    /* Slave → Master */
    uint8_t pong[] = "encrypted-pong";
    rc = sprotocol_send(slave1->h, SPROTOCOL_ADDR_MASTER, SPROTOCOL_DOMAIN_OTA,
                        SPROTOCOL_MSG_DATA, pong, sizeof(pong));
    REPORT("slave encrypted send OK", rc == SPROTOCOL_OK);

    waited = 0;
    while (master->recv_count == 0 && waited < 1000) { sleep_ms(10); waited += 10; }
    pthread_mutex_lock(&master->m);
    int ok2 = (master->last_len == sizeof(pong)) &&
              (memcmp(master->last_payload, pong, sizeof(pong)) == 0);
    pthread_mutex_unlock(&master->m);
    REPORT("master decrypted slave plaintext", ok2);
}

/* ---------- 序列号 ---------- */

static void test_sequence_increment(node_t* master)
{
    uint16_t s0 = sprotocol_get_tx_seq(master->h, 0x10);
    sprotocol_send(master->h, 0x10, SPROTOCOL_DOMAIN_BASE,
                   SPROTOCOL_MSG_DATA, (const uint8_t*)"a", 1);
    sprotocol_send(master->h, 0x10, SPROTOCOL_DOMAIN_BASE,
                   SPROTOCOL_MSG_DATA, (const uint8_t*)"b", 1);
    uint16_t s1 = sprotocol_get_tx_seq(master->h, 0x10);
    REPORT("seq increments by 2", (uint16_t)(s1 - s0) == 2);
}

/* ---------- 心跳超时 / 在线状态 ---------- */

static int pred_master_offline(void* ud)
{
    node_t* m = (node_t*)ud;
    return !sprotocol_is_device_online(m->h, 0x10);
}

static void test_heartbeat_offline(node_t* master, node_t* slave1)
{
    /* 当前 slave1 已在线。阻断 slave1 的出站，让 master 收不到任何帧 → 超时 */
    udp_link_set_tx_drop(slave1->link, 1);

    /* 等待心跳超时（master 的 heartbeat_timeout 是 500ms） */
    bool ok = wait_until(2000, pred_master_offline, master);
    REPORT("master detects slave offline on heartbeat timeout", ok);

    /* 恢复链路 */
    udp_link_set_tx_drop(slave1->link, 0);

    /* 让 slave 主动发心跳，master 重新上线 */
    int rc = sprotocol_send_heartbeat(slave1->h);
    REPORT("slave_heartbeat explicit send OK", rc == SPROTOCOL_OK);

    int waited = 0;
    while (!sprotocol_is_device_online(master->h, 0x10) && waited < 1000) {
        sleep_ms(10); waited += 10;
    }
    REPORT("master sees slave online again", sprotocol_is_device_online(master->h, 0x10));
}

/* ---------- 删除设备 ---------- */

static void test_remove_device(node_t* master)
{
    int rc = sprotocol_remove_device(master->h, 0x10);
    REPORT("remove_device OK", rc == SPROTOCOL_OK);
    REPORT("device gone after remove",
           sprotocol_get_device(master->h, 0x10) == NULL);

    rc = sprotocol_remove_device(master->h, 0x10);
    REPORT("remove_device twice -> NOT_FOUND", rc == SPROTOCOL_ERR_NOT_FOUND);

    sprotocol_remove_all_devices(master->h);
    uint8_t addrs[8];
    int n = sprotocol_get_paired_devices(master->h, addrs, 8);
    REPORT("remove_all empties list", n == 0);
}

/* ---------- 黑名单基础（API 层面） ---------- */

static void test_blacklist_api(node_t* master)
{
    REPORT("blacklist empty initially",
           sprotocol_get_blacklist_count(master->h) == 0);
    REPORT("is_blacklisted(0x10) == 0",
           sprotocol_is_blacklisted(master->h, 0x10) == 0);
}

/* ============================================================ */
/* 入口                                                         */
/* ============================================================ */

int main(void)
{
    printf("=== sprotocol test suite ===\n");
    printf("version: %s\n", sprotocol_get_version());

    /* 先跑不依赖网络的用例 */
    test_crc16();
    test_version();
    test_invalid_init();

    /* 启动 master + 2 slaves（心跳超时 500ms，配对超时 2s，启用加密） */
    node_t* master = node_new_master("master", 2, 500, 2000, 1);
    node_t* slave1 = node_new_slave("slave1", 0x10, 3000, 2000, 1);
    node_t* slave2 = node_new_slave("slave2", 0x11, 3000, 2000, 1);
    if (!master || !slave1 || !slave2) {
        fprintf(stderr, "ERROR: cannot create nodes (port in use?)\n");
        return 2;
    }
    g_master = master;

    atomic_store(&g_poll_running, 1);
    pthread_create(&g_poll_thread, NULL, poll_loop, NULL);

    test_blacklist_api(master);
    test_single_pair(master, slave1);
    test_multi_pair(master, slave2);
    test_invalid_pair_addr();
    test_basic_data(master, slave1);
    test_broadcast(master, slave1, slave2);
    test_sequence_increment(master);
    test_encrypted_roundtrip(master, slave1);
    test_heartbeat_offline(master, slave1);
    test_remove_device(master);

    /* 收尾 */
    atomic_store(&g_poll_running, 0);
    pthread_join(g_poll_thread, NULL);

    for (int i = 0; i < g_node_count; ++i) {
        node_free(g_nodes[i]);
        g_nodes[i] = NULL;
    }

    printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
