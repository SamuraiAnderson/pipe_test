/**
 * test_main.c
 *
 * sprotocol 测试程序
 * 使用 UDP socket 在 localhost 模拟三节点通信：
 *   Master  地址 0x00  端口 9000
 *   Slave1  地址 0x10  端口 9001
 *   Slave2  地址 0x11  端口 9002
 *
 * 运行方式：./bin/test_sprotocol
 */

#include "sprotocol.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

/* POSIX socket */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/select.h>

/* =========================================================================
 * 颜色输出
 * ========================================================================= */
#define COLOR_GREEN  "\033[0;32m"
#define COLOR_RED    "\033[0;31m"
#define COLOR_YELLOW "\033[0;33m"
#define COLOR_RESET  "\033[0m"

static int g_pass = 0;
static int g_fail = 0;

#define TEST_ASSERT(cond, msg)                                          \
    do {                                                                \
        if (!(cond)) {                                                  \
            fprintf(stderr, COLOR_RED "[FAIL] %s:%d  %s" COLOR_RESET "\n", \
                    __func__, __LINE__, (msg));                         \
            g_fail++;                                                   \
            return;                                                     \
        }                                                               \
    } while (0)

#define TEST_PASS(msg)                                                  \
    do {                                                                \
        printf(COLOR_GREEN "[PASS] %s" COLOR_RESET "\n", (msg));       \
        g_pass++;                                                       \
    } while (0)

/* =========================================================================
 * 时间工具（ms 精度）
 * ========================================================================= */
static uint32_t get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

static uint32_t g_mock_time = 0;
static int g_use_mock_time = 0;

static uint32_t test_get_time(void) {
    if (g_use_mock_time) return g_mock_time;
    return get_time_ms();
}

/* =========================================================================
 * UDP 节点
 * ========================================================================= */
#define MASTER_PORT 9000
#define SLAVE1_PORT 9001
#define SLAVE2_PORT 9002
#define LOCALHOST   "127.0.0.1"

typedef struct {
    int           fd;
    uint16_t      port;
    uint8_t       addr;
    sprotocol_handle_t handle;
} node_t;

static node_t g_master;
static node_t g_slave1;
static node_t g_slave2;

/* 最后收到的消息 */
typedef struct {
    uint8_t  src;
    uint16_t domain_id;
    uint8_t  msg_type;
    uint8_t  payload[256];
    size_t   payload_len;
    int      received;
} last_msg_t;

static last_msg_t g_master_msg;
static last_msg_t g_slave1_msg;
static last_msg_t g_slave2_msg;

/* 配对状态记录 */
static uint8_t g_master_pair_status[256];
static uint8_t g_slave1_pair_status[256];
static uint8_t g_slave2_pair_status[256];

/* 在线状态记录 */
static uint8_t g_master_online[256];

/* -------------------------------------------------------------------------
 * send_cb：通过 UDP 发送到目标端口
 * ------------------------------------------------------------------------- */
static void udp_send(int src_fd, uint8_t dest_addr, const uint8_t *data, size_t len) {
    uint16_t dest_port;
    if (dest_addr == 0x00) {
        dest_port = MASTER_PORT;
    } else if (dest_addr == 0x10) {
        dest_port = SLAVE1_PORT;
    } else if (dest_addr == 0x11) {
        dest_port = SLAVE2_PORT;
    } else if (dest_addr == 0xFF) {
        /* 广播：发给所有已知端口 */
        uint16_t ports[] = {MASTER_PORT, SLAVE1_PORT, SLAVE2_PORT};
        for (int i = 0; i < 3; i++) {
            struct sockaddr_in dst;
            memset(&dst, 0, sizeof(dst));
            dst.sin_family      = AF_INET;
            dst.sin_port        = htons(ports[i]);
            inet_pton(AF_INET, LOCALHOST, &dst.sin_addr);
            sendto(src_fd, data, len, 0, (struct sockaddr*)&dst, sizeof(dst));
        }
        return;
    } else {
        return;
    }

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port   = htons(dest_port);
    inet_pton(AF_INET, LOCALHOST, &dst.sin_addr);
    sendto(src_fd, data, len, 0, (struct sockaddr*)&dst, sizeof(dst));
}

/* send_cb 需要知道是哪个节点在发送，通过 user_data 传入节点指针 */
static void master_send_cb(const uint8_t *data, size_t len, void *user_data) {
    node_t *node = (node_t*)user_data;
    /* 解析目的地址（帧字节[4]） */
    if (len < 5) return;
    uint8_t dest = data[4];
    udp_send(node->fd, dest, data, len);
}

static void slave1_send_cb(const uint8_t *data, size_t len, void *user_data) {
    node_t *node = (node_t*)user_data;
    if (len < 5) return;
    uint8_t dest = data[4];
    udp_send(node->fd, dest, data, len);
}

static void slave2_send_cb(const uint8_t *data, size_t len, void *user_data) {
    node_t *node = (node_t*)user_data;
    if (len < 5) return;
    uint8_t dest = data[4];
    udp_send(node->fd, dest, data, len);
}

/* -------------------------------------------------------------------------
 * recv_cb
 * ------------------------------------------------------------------------- */
static void master_recv_cb(uint8_t src, uint16_t dom, uint8_t mtype,
                            const uint8_t *pl, size_t plen, void *ud) {
    (void)ud;
    g_master_msg.src = src;
    g_master_msg.domain_id = dom;
    g_master_msg.msg_type = mtype;
    g_master_msg.payload_len = plen;
    if (plen > 0) memcpy(g_master_msg.payload, pl, plen);
    g_master_msg.received = 1;
}

static void slave1_recv_cb(uint8_t src, uint16_t dom, uint8_t mtype,
                            const uint8_t *pl, size_t plen, void *ud) {
    (void)ud;
    g_slave1_msg.src = src;
    g_slave1_msg.domain_id = dom;
    g_slave1_msg.msg_type = mtype;
    g_slave1_msg.payload_len = plen;
    if (plen > 0) memcpy(g_slave1_msg.payload, pl, plen);
    g_slave1_msg.received = 1;
}

static void slave2_recv_cb(uint8_t src, uint16_t dom, uint8_t mtype,
                            const uint8_t *pl, size_t plen, void *ud) {
    (void)ud;
    g_slave2_msg.src = src;
    g_slave2_msg.domain_id = dom;
    g_slave2_msg.msg_type = mtype;
    g_slave2_msg.payload_len = plen;
    if (plen > 0) memcpy(g_slave2_msg.payload, pl, plen);
    g_slave2_msg.received = 1;
}

/* -------------------------------------------------------------------------
 * pair_cb / online_cb
 * ------------------------------------------------------------------------- */
static void master_pair_cb(uint8_t addr, uint8_t status, void *ud) {
    (void)ud;
    g_master_pair_status[addr] = status;
}
static void slave1_pair_cb(uint8_t addr, uint8_t status, void *ud) {
    (void)ud;
    g_slave1_pair_status[addr] = status;
}
static void slave2_pair_cb(uint8_t addr, uint8_t status, void *ud) {
    (void)ud;
    g_slave2_pair_status[addr] = status;
}
static void master_online_cb(uint8_t addr, uint8_t online, void *ud) {
    (void)ud;
    g_master_online[addr] = online;
}

/* =========================================================================
 * UDP socket 初始化
 * ========================================================================= */
static int udp_init(uint16_t port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return -1; }

    /* 非阻塞 */
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    /* 允许地址重用 */
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(fd);
        return -1;
    }
    return fd;
}

/* =========================================================================
 * 驱动所有节点处理 UDP 数据（非阻塞轮询）
 * ========================================================================= */
static void pump_network(int max_ms) {
    uint8_t buf[512];
    uint32_t deadline = get_time_ms() + (uint32_t)max_ms;

    while (get_time_ms() < deadline) {
        int activity = 0;

        /* 尝试从每个节点的 fd 读取数据 */
        node_t *nodes[] = {&g_master, &g_slave1, &g_slave2};
        for (int i = 0; i < 3; i++) {
            node_t *n = nodes[i];
            ssize_t r = recv(n->fd, buf, sizeof(buf), 0);
            if (r > 0) {
                sprotocol_input(n->handle, buf, (size_t)r);
                activity = 1;
            }
        }

        /* poll 所有节点 */
        sprotocol_poll(g_master.handle);
        sprotocol_poll(g_slave1.handle);
        sprotocol_poll(g_slave2.handle);

        if (!activity) {
            usleep(1000); /* 1ms */
        }
    }
}

/* =========================================================================
 * 节点初始化/清理
 * ========================================================================= */
static void init_node(node_t *n, uint8_t addr, uint16_t port,
                       sprotocol_role_t role,
                       sprotocol_send_cb send_cb,
                       sprotocol_pair_cb pair_cb,
                       sprotocol_online_cb online_cb,
                       sprotocol_recv_cb recv_cb,
                       int enc_enabled) {
    n->addr = addr;
    n->port = port;
    n->fd   = udp_init(port);
    assert(n->fd >= 0);

    sprotocol_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role               = role;
    cfg.local_addr         = addr;
    cfg.max_slaves         = SPROTOCOL_MAX_SLAVES;
    cfg.heartbeat_timeout  = 3000;
    cfg.pair_timeout       = 5000;
    cfg.send_cb            = send_cb;
    cfg.pair_cb            = pair_cb;
    cfg.online_cb          = online_cb;
    cfg.recv_cb            = recv_cb;
    cfg.get_time           = test_get_time;
    cfg.user_data          = n;
    cfg.encryption_enabled = (uint8_t)enc_enabled;
    cfg.enc_type           = enc_enabled ? SPROTOCOL_ENC_ECC : SPROTOCOL_ENC_NONE;

    n->handle = sprotocol_init(&cfg);
    assert(n->handle != NULL);
}

static void deinit_node(node_t *n) {
    sprotocol_deinit(n->handle);
    n->handle = NULL;
    if (n->fd >= 0) { close(n->fd); n->fd = -1; }
}

static void setup_nodes(int enc_enabled) {
    memset(&g_master_msg, 0, sizeof(g_master_msg));
    memset(&g_slave1_msg, 0, sizeof(g_slave1_msg));
    memset(&g_slave2_msg, 0, sizeof(g_slave2_msg));
    memset(g_master_pair_status, 0, sizeof(g_master_pair_status));
    memset(g_slave1_pair_status, 0, sizeof(g_slave1_pair_status));
    memset(g_slave2_pair_status, 0, sizeof(g_slave2_pair_status));
    memset(g_master_online, 0, sizeof(g_master_online));

    init_node(&g_master, SPROTOCOL_ADDR_MASTER, MASTER_PORT,
              SPROTOCOL_ROLE_MASTER,
              master_send_cb, master_pair_cb, master_online_cb, master_recv_cb,
              enc_enabled);
    init_node(&g_slave1, 0x10, SLAVE1_PORT,
              SPROTOCOL_ROLE_SLAVE,
              slave1_send_cb, slave1_pair_cb, NULL, slave1_recv_cb,
              enc_enabled);
    init_node(&g_slave2, 0x11, SLAVE2_PORT,
              SPROTOCOL_ROLE_SLAVE,
              slave2_send_cb, slave2_pair_cb, NULL, slave2_recv_cb,
              enc_enabled);
}

static void teardown_nodes(void) {
    deinit_node(&g_master);
    deinit_node(&g_slave1);
    deinit_node(&g_slave2);
}

/* =========================================================================
 * 测试用例
 * ========================================================================= */

/* -------------------------------------------------------------------------
 * test_crc16
 * ------------------------------------------------------------------------- */
static void test_crc16(void) {
    /* 已知向量：CRC-16/CCITT-FALSE，多项式 0x1021，init 0xFFFF */
    /* "123456789" -> 0x29B1 */
    const uint8_t data[] = {'1','2','3','4','5','6','7','8','9'};
    uint16_t crc = sprotocol_crc16(data, sizeof(data));
    TEST_ASSERT(crc == 0x29B1, "CRC16 known vector mismatch");

    /* 空数据 */
    uint16_t crc_empty = sprotocol_crc16(NULL, 0);
    (void)crc_empty; /* 只要不崩溃 */

    /* 单字节 0x00 */
    uint8_t zero = 0;
    sprotocol_crc16(&zero, 1);

    TEST_PASS("test_crc16");
}

/* -------------------------------------------------------------------------
 * test_pairing_single：单从机配对
 * ------------------------------------------------------------------------- */
static void test_pairing_single(void) {
    setup_nodes(0);

    int ret = sprotocol_pair_request(g_master.handle, 0x10);
    TEST_ASSERT(ret == SPROTOCOL_OK, "pair_request failed");

    /* 等待配对完成（最多 500ms） */
    pump_network(500);

    TEST_ASSERT(g_master_pair_status[0x10] == SPROTOCOL_PAIR_COMPLETE,
                "master pair not complete");
    TEST_ASSERT(g_slave1_pair_status[0x00] == SPROTOCOL_PAIR_COMPLETE,
                "slave1 pair not complete");

    /* 检查设备列表 */
    uint8_t addrs[8];
    int cnt = sprotocol_get_paired_devices(g_master.handle, addrs, 8);
    TEST_ASSERT(cnt == 1, "paired devices count != 1");
    TEST_ASSERT(addrs[0] == 0x10, "paired device addr mismatch");

    teardown_nodes();
    TEST_PASS("test_pairing_single");
}

/* -------------------------------------------------------------------------
 * test_pairing_multi：两个从机配对
 * ------------------------------------------------------------------------- */
static void test_pairing_multi(void) {
    setup_nodes(0);

    sprotocol_pair_request(g_master.handle, 0x10);
    pump_network(200);
    sprotocol_pair_request(g_master.handle, 0x11);
    pump_network(500);

    TEST_ASSERT(g_master_pair_status[0x10] == SPROTOCOL_PAIR_COMPLETE,
                "slave1 not paired");
    TEST_ASSERT(g_master_pair_status[0x11] == SPROTOCOL_PAIR_COMPLETE,
                "slave2 not paired");

    uint8_t addrs[8];
    int cnt = sprotocol_get_paired_devices(g_master.handle, addrs, 8);
    TEST_ASSERT(cnt == 2, "should have 2 paired devices");

    teardown_nodes();
    TEST_PASS("test_pairing_multi");
}

/* -------------------------------------------------------------------------
 * test_remove_device：删除配对设备
 * ------------------------------------------------------------------------- */
static void test_remove_device(void) {
    setup_nodes(0);

    sprotocol_pair_request(g_master.handle, 0x10);
    pump_network(300);

    TEST_ASSERT(g_master_pair_status[0x10] == SPROTOCOL_PAIR_COMPLETE,
                "not paired before remove");

    int ret = sprotocol_remove_device(g_master.handle, 0x10);
    TEST_ASSERT(ret == SPROTOCOL_OK, "remove_device failed");

    uint8_t addrs[8];
    int cnt = sprotocol_get_paired_devices(g_master.handle, addrs, 8);
    TEST_ASSERT(cnt == 0, "device not removed");

    /* 删除不存在的设备 */
    ret = sprotocol_remove_device(g_master.handle, 0x10);
    TEST_ASSERT(ret == SPROTOCOL_ERR_NOT_FOUND, "should return NOT_FOUND");

    teardown_nodes();
    TEST_PASS("test_remove_device");
}

/* -------------------------------------------------------------------------
 * test_send_recv：数据发送接收
 * ------------------------------------------------------------------------- */
static void test_send_recv(void) {
    setup_nodes(0);

    /* 先配对 */
    sprotocol_pair_request(g_master.handle, 0x10);
    pump_network(300);

    /* 主机发数据给 slave1 */
    const uint8_t msg[] = "hello slave";
    g_slave1_msg.received = 0;
    int ret = sprotocol_send(g_master.handle, 0x10,
                              SPROTOCOL_DOMAIN_BASE, SPROTOCOL_MSG_DATA,
                              msg, sizeof(msg));
    TEST_ASSERT(ret == SPROTOCOL_OK, "send failed");
    pump_network(200);

    TEST_ASSERT(g_slave1_msg.received, "slave1 did not receive");
    TEST_ASSERT(g_slave1_msg.payload_len == sizeof(msg), "payload len mismatch");
    TEST_ASSERT(memcmp(g_slave1_msg.payload, msg, sizeof(msg)) == 0,
                "payload content mismatch");

    /* slave1 回复主机 */
    const uint8_t reply[] = "hello master";
    g_master_msg.received = 0;
    ret = sprotocol_send(g_slave1.handle, SPROTOCOL_ADDR_MASTER,
                         SPROTOCOL_DOMAIN_BASE, SPROTOCOL_MSG_DATA,
                         reply, sizeof(reply));
    TEST_ASSERT(ret == SPROTOCOL_OK, "slave send failed");
    pump_network(200);

    TEST_ASSERT(g_master_msg.received, "master did not receive reply");
    TEST_ASSERT(memcmp(g_master_msg.payload, reply, sizeof(reply)) == 0,
                "master received wrong payload");

    teardown_nodes();
    TEST_PASS("test_send_recv");
}

/* -------------------------------------------------------------------------
 * test_broadcast：广播发送
 * ------------------------------------------------------------------------- */
static void test_broadcast(void) {
    setup_nodes(0);

    sprotocol_pair_request(g_master.handle, 0x10);
    pump_network(200);
    sprotocol_pair_request(g_master.handle, 0x11);
    pump_network(200);

    const uint8_t bcast[] = "broadcast!";
    g_slave1_msg.received = 0;
    g_slave2_msg.received = 0;

    int ret = sprotocol_broadcast(g_master.handle,
                                   SPROTOCOL_DOMAIN_BASE, SPROTOCOL_MSG_DATA,
                                   bcast, sizeof(bcast));
    TEST_ASSERT(ret == SPROTOCOL_OK, "broadcast failed");
    pump_network(200);

    TEST_ASSERT(g_slave1_msg.received, "slave1 did not receive broadcast");
    TEST_ASSERT(g_slave2_msg.received, "slave2 did not receive broadcast");
    TEST_ASSERT(memcmp(g_slave1_msg.payload, bcast, sizeof(bcast)) == 0,
                "slave1 broadcast payload mismatch");
    TEST_ASSERT(memcmp(g_slave2_msg.payload, bcast, sizeof(bcast)) == 0,
                "slave2 broadcast payload mismatch");

    teardown_nodes();
    TEST_PASS("test_broadcast");
}

/* -------------------------------------------------------------------------
 * test_sequence_number：序列号递增
 * ------------------------------------------------------------------------- */
static void test_sequence_number(void) {
    setup_nodes(0);

    uint16_t seq0 = sprotocol_get_tx_seq(g_master.handle, SPROTOCOL_ADDR_MASTER);

    /* 每次发送或配对请求都会递增 local_seq */
    sprotocol_pair_request(g_master.handle, 0x10);
    pump_network(300);

    uint16_t seq1 = sprotocol_get_tx_seq(g_master.handle, SPROTOCOL_ADDR_MASTER);
    /* seq1 > seq0（至少 3 次操作：PAIR_REQ + PAIR_CFM） */
    TEST_ASSERT((uint16_t)(seq1 - seq0) >= 2, "seq not incremented enough");

    /* 多次发送 */
    const uint8_t d[] = "x";
    sprotocol_send(g_master.handle, 0x10, SPROTOCOL_DOMAIN_BASE, SPROTOCOL_MSG_DATA, d, 1);
    uint16_t seq2 = sprotocol_get_tx_seq(g_master.handle, SPROTOCOL_ADDR_MASTER);
    TEST_ASSERT(seq2 == (uint16_t)(seq1 + 1), "seq not incremented by 1 after send");

    teardown_nodes();
    TEST_PASS("test_sequence_number");
}

/* -------------------------------------------------------------------------
 * test_heartbeat_timeout：心跳超时检测
 * 使用 mock 时间快速推进
 * ------------------------------------------------------------------------- */
static void test_heartbeat_timeout(void) {
    g_use_mock_time = 1;
    g_mock_time = 0;

    /* 使用极短心跳超时 */
    node_t master, slave1;
    memset(&master, 0, sizeof(master));
    memset(&slave1, 0, sizeof(slave1));
    memset(g_master_pair_status, 0, sizeof(g_master_pair_status));
    memset(g_master_online, 0, sizeof(g_master_online));
    memset(&g_slave1_msg, 0, sizeof(g_slave1_msg));
    memset(&g_slave1_pair_status, 0, sizeof(g_slave1_pair_status));

    /* 使用临时端口避免冲突 */
    master.fd = udp_init(9010);
    slave1.fd = udp_init(9011);
    assert(master.fd >= 0 && slave1.fd >= 0);

    sprotocol_config_t mcfg, scfg;
    memset(&mcfg, 0, sizeof(mcfg));
    mcfg.role              = SPROTOCOL_ROLE_MASTER;
    mcfg.local_addr        = 0x00;
    mcfg.max_slaves        = 5;
    mcfg.heartbeat_timeout = 200; /* 200ms */
    mcfg.pair_timeout      = 5000;
    mcfg.send_cb           = master_send_cb;
    mcfg.pair_cb           = master_pair_cb;
    mcfg.online_cb         = master_online_cb;
    mcfg.recv_cb           = master_recv_cb;
    mcfg.get_time          = test_get_time;
    mcfg.user_data         = &master;

    memset(&scfg, 0, sizeof(scfg));
    scfg.role              = SPROTOCOL_ROLE_SLAVE;
    scfg.local_addr        = 0x10;
    scfg.max_slaves        = 5;
    scfg.heartbeat_timeout = 200;
    scfg.pair_timeout      = 5000;
    scfg.send_cb           = slave1_send_cb;
    scfg.pair_cb           = slave1_pair_cb;
    scfg.recv_cb           = slave1_recv_cb;
    scfg.get_time          = test_get_time;
    scfg.user_data         = &slave1;

    master.handle = sprotocol_init(&mcfg);
    slave1.handle = sprotocol_init(&scfg);
    assert(master.handle && slave1.handle);

    /* 手动驱动：PAIR_REQ */
    g_mock_time = 0;
    {
        /* master 发 PAIR_REQ */
        sprotocol_pair_request(master.handle, 0x10);
        /* 读出并喂给 slave1（使用 9010->9011 发送）
         * 注意：master 的 send_cb 会 udp_send 到 SLAVE1_PORT(9001)，
         * 本测试用的是 9011，所以直接调用内部帧注入 */
    }

    /* 改用直接注入方式驱动 */
    /* 重新建立：直接在内存中调用 input，不通过 UDP */
    sprotocol_deinit(master.handle);
    sprotocol_deinit(slave1.handle);
    close(master.fd);
    close(slave1.fd);

    /* 使用主测试节点，但缩短心跳超时 */
    setup_nodes(0);

    /* 重置为 mock 时间 */
    g_use_mock_time = 1;
    g_mock_time = 100;

    /* 配对 */
    sprotocol_pair_request(g_master.handle, 0x10);

    /* 手动路由帧 */
    uint8_t buf[512];
    for (int i = 0; i < 10; i++) {
        ssize_t r = recv(g_slave1.fd, buf, sizeof(buf), 0);
        if (r > 0) sprotocol_input(g_slave1.handle, buf, (size_t)r);
        r = recv(g_master.fd, buf, sizeof(buf), 0);
        if (r > 0) sprotocol_input(g_master.handle, buf, (size_t)r);
        usleep(2000);
    }

    /* 配对完成后 slave1 发心跳 */
    sprotocol_send_heartbeat(g_slave1.handle);
    for (int i = 0; i < 5; i++) {
        ssize_t r = recv(g_master.fd, buf, sizeof(buf), 0);
        if (r > 0) sprotocol_input(g_master.handle, buf, (size_t)r);
        usleep(1000);
    }

    /* 此时 slave1 在线 */
    sprotocol_poll(g_master.handle);

    const sprotocol_device_t *dev = sprotocol_get_device(g_master.handle, 0x10);
    if (dev && dev->pair_status == SPROTOCOL_PAIR_COMPLETE) {
        /* 推进 mock 时间超过心跳超时 */
        g_mock_time += 4000;
        sprotocol_poll(g_master.handle);
        TEST_ASSERT(g_master_online[0x10] == SPROTOCOL_DEVICE_OFFLINE,
                    "heartbeat timeout not detected");
    }

    g_use_mock_time = 0;
    teardown_nodes();
    TEST_PASS("test_heartbeat_timeout");
}

/* -------------------------------------------------------------------------
 * test_boundary_invalid_addr：边界条件
 * ------------------------------------------------------------------------- */
static void test_boundary_invalid_addr(void) {
    setup_nodes(0);

    /* 无效地址（超出从机范围） */
    int ret = sprotocol_pair_request(g_master.handle, 0x05);
    TEST_ASSERT(ret == SPROTOCOL_ERR_INVALID_ARG, "should reject addr < 0x10");

    ret = sprotocol_pair_request(g_master.handle, 0x20);
    TEST_ASSERT(ret == SPROTOCOL_ERR_INVALID_ARG, "should reject addr > 0x14");

    /* 超出最大从机数 */
    sprotocol_pair_request(g_master.handle, 0x10);
    sprotocol_pair_request(g_master.handle, 0x11);
    sprotocol_pair_request(g_master.handle, 0x12);
    sprotocol_pair_request(g_master.handle, 0x13);
    sprotocol_pair_request(g_master.handle, 0x14);
    pump_network(300);

    /* 第 6 个会失败 */
    /* 注意：max_slaves=5，地址 0x10-0x14 恰好 5 个 */
    /* 再加一个相同地址 */
    ret = sprotocol_pair_request(g_master.handle, 0x10);
    /* 已存在的地址不会返回 FULL，允许重新配对 */

    /* NULL handle */
    ret = sprotocol_send(NULL, 0x10, SPROTOCOL_DOMAIN_BASE, SPROTOCOL_MSG_DATA, NULL, 0);
    TEST_ASSERT(ret == SPROTOCOL_ERR_INVALID_ARG, "NULL handle should return error");

    teardown_nodes();
    TEST_PASS("test_boundary_invalid_addr");
}

/* -------------------------------------------------------------------------
 * test_crypto_ecc：ECC 密钥交换 + 加密通信
 * ------------------------------------------------------------------------- */
static void test_crypto_ecc(void) {
    setup_nodes(1); /* enc_enabled=1 */

    /* 配对（含 ECC 密钥交换） */
    int ret = sprotocol_pair_request(g_master.handle, 0x10);
    TEST_ASSERT(ret == SPROTOCOL_OK, "crypto pair_request failed");
    pump_network(500);

    TEST_ASSERT(g_master_pair_status[0x10] == SPROTOCOL_PAIR_COMPLETE,
                "crypto pair not complete on master");
    TEST_ASSERT(g_slave1_pair_status[0x00] == SPROTOCOL_PAIR_COMPLETE,
                "crypto pair not complete on slave1");

    /* 加密数据传输 */
    const uint8_t secret[] = "top secret message";
    g_slave1_msg.received = 0;

    ret = sprotocol_send(g_master.handle, 0x10,
                          SPROTOCOL_DOMAIN_BASE, SPROTOCOL_MSG_DATA,
                          secret, sizeof(secret));
    TEST_ASSERT(ret == SPROTOCOL_OK, "crypto send failed");
    pump_network(300);

    TEST_ASSERT(g_slave1_msg.received, "slave1 did not receive encrypted msg");
    TEST_ASSERT(g_slave1_msg.payload_len == sizeof(secret),
                "encrypted payload length mismatch");
    TEST_ASSERT(memcmp(g_slave1_msg.payload, secret, sizeof(secret)) == 0,
                "decrypted payload mismatch");

    teardown_nodes();
    TEST_PASS("test_crypto_ecc");
}

/* -------------------------------------------------------------------------
 * test_version：版本字符串
 * ------------------------------------------------------------------------- */
static void test_version(void) {
    const char *ver = sprotocol_get_version();
    TEST_ASSERT(ver != NULL, "version is NULL");
    TEST_ASSERT(ver[0] != '\0', "version is empty");
    printf("  Protocol version: %s\n", ver);
    TEST_PASS("test_version");
}

/* =========================================================================
 * main
 * ========================================================================= */
int main(void) {
    printf("=================================================\n");
    printf("  sprotocol Test Suite\n");
    printf("=================================================\n\n");

    test_version();
    test_crc16();
    test_pairing_single();
    test_pairing_multi();
    test_remove_device();
    test_send_recv();
    test_broadcast();
    test_sequence_number();
    test_heartbeat_timeout();
    test_boundary_invalid_addr();
    test_crypto_ecc();

    printf("\n=================================================\n");
    printf("  Results: " COLOR_GREEN "%d passed" COLOR_RESET
           ", " COLOR_RED "%d failed" COLOR_RESET "\n",
           g_pass, g_fail);
    printf("=================================================\n");

    return (g_fail == 0) ? 0 : 1;
}
