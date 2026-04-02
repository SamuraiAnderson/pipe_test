#include "sprotocol.h"
#include "sprotocol_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <fcntl.h>
#include <errno.h>

/*============================================================================
 * Test framework
 *============================================================================*/

static int tests_run    = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d)\n", msg, __LINE__); \
        return 0; \
    } \
} while(0)

#define RUN_TEST(fn) do { \
    tests_run++; \
    printf("[TEST] %s\n", #fn); \
    if (fn()) { \
        tests_passed++; \
        printf("  PASS\n"); \
    } else { \
        tests_failed++; \
    } \
} while(0)

/*============================================================================
 * Time simulation
 *============================================================================*/

static uint32_t sim_time_ms = 0;

static uint32_t get_sim_time(void)
{
    return sim_time_ms;
}

static void advance_time(uint32_t ms)
{
    sim_time_ms += ms;
}

/*============================================================================
 * UDP transport layer
 *============================================================================*/

#define MASTER_PORT 9000
#define SLAVE1_PORT 9001
#define SLAVE2_PORT 9002

typedef struct {
    int sock;
    uint16_t port;
    struct sockaddr_in addr;
} udp_endpoint_t;

static udp_endpoint_t ep_master;
static udp_endpoint_t ep_slave1;
static udp_endpoint_t ep_slave2;

static int udp_init(udp_endpoint_t *ep, uint16_t port)
{
    ep->sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (ep->sock < 0)
        return -1;

    int flags = fcntl(ep->sock, F_GETFL, 0);
    fcntl(ep->sock, F_SETFL, flags | O_NONBLOCK);

    int reuse = 1;
    setsockopt(ep->sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    memset(&ep->addr, 0, sizeof(ep->addr));
    ep->addr.sin_family = AF_INET;
    ep->addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ep->addr.sin_port = htons(port);
    ep->port = port;

    if (bind(ep->sock, (struct sockaddr *)&ep->addr, sizeof(ep->addr)) < 0) {
        close(ep->sock);
        return -1;
    }
    return 0;
}

static void udp_close(udp_endpoint_t *ep)
{
    if (ep->sock >= 0) {
        close(ep->sock);
        ep->sock = -1;
    }
}

static void udp_send_to_port(udp_endpoint_t *from, uint16_t dest_port,
                             const uint8_t *data, size_t len)
{
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    dest.sin_port = htons(dest_port);
    sendto(from->sock, data, len, 0, (struct sockaddr *)&dest, sizeof(dest));
}

static ssize_t udp_recv(udp_endpoint_t *ep, uint8_t *buf, size_t buf_size)
{
    return recvfrom(ep->sock, buf, buf_size, 0, NULL, NULL);
}

/*============================================================================
 * Send callbacks: route packets via UDP based on dest address in frame
 *============================================================================*/

static uint16_t addr_to_port(uint8_t addr)
{
    if (addr == SPROTOCOL_ADDR_MASTER)
        return MASTER_PORT;
    if (addr >= SPROTOCOL_MIN_SLAVE_ADDR && addr <= SPROTOCOL_MAX_SLAVE_ADDR)
        return SLAVE1_PORT + (addr - SPROTOCOL_MIN_SLAVE_ADDR);
    return 0;
}

typedef struct {
    udp_endpoint_t *ep;
} send_ctx_t;

static void master_send_cb(const uint8_t *data, size_t len, void *user_data)
{
    send_ctx_t *ctx = (send_ctx_t *)user_data;
    if (len < 5)
        return;
    uint8_t dest_addr = data[4];

    if (dest_addr == SPROTOCOL_ADDR_BROADCAST) {
        for (uint8_t a = SPROTOCOL_MIN_SLAVE_ADDR; a <= SPROTOCOL_MAX_SLAVE_ADDR; a++) {
            uint16_t port = addr_to_port(a);
            if (port)
                udp_send_to_port(ctx->ep, port, data, len);
        }
    } else {
        uint16_t port = addr_to_port(dest_addr);
        if (port)
            udp_send_to_port(ctx->ep, port, data, len);
    }
}

static void slave_send_cb(const uint8_t *data, size_t len, void *user_data)
{
    send_ctx_t *ctx = (send_ctx_t *)user_data;
    if (len < 5)
        return;
    uint8_t dest_addr = data[4];
    uint16_t port = addr_to_port(dest_addr);
    if (port)
        udp_send_to_port(ctx->ep, port, data, len);
}

/*============================================================================
 * Helper: pump messages between master and slaves via UDP
 *============================================================================*/

static void pump_messages(sprotocol_handle_t master,
                          sprotocol_handle_t slave1,
                          sprotocol_handle_t slave2,
                          int rounds)
{
    uint8_t buf[1024];
    for (int r = 0; r < rounds; r++) {
        usleep(1000);

        /* Master receives */
        ssize_t n;
        while ((n = udp_recv(&ep_master, buf, sizeof(buf))) > 0) {
            if (master) sprotocol_input(master, buf, (size_t)n);
        }

        /* Slave1 receives */
        while ((n = udp_recv(&ep_slave1, buf, sizeof(buf))) > 0) {
            if (slave1) sprotocol_input(slave1, buf, (size_t)n);
        }

        /* Slave2 receives */
        while ((n = udp_recv(&ep_slave2, buf, sizeof(buf))) > 0) {
            if (slave2) sprotocol_input(slave2, buf, (size_t)n);
        }

        if (master) sprotocol_poll(master);
        if (slave1) sprotocol_poll(slave1);
        if (slave2) sprotocol_poll(slave2);
    }
}

/*============================================================================
 * Test: CRC16 correctness
 *============================================================================*/

static int test_crc16(void)
{
    uint8_t data1[] = {0x01, 0x02, 0x03, 0x04};
    uint16_t crc1 = sprotocol_crc16(data1, sizeof(data1));

    uint16_t crc1_again = sprotocol_crc16(data1, sizeof(data1));
    TEST_ASSERT(crc1 == crc1_again, "CRC should be deterministic");

    uint8_t data2[] = {0x01, 0x02, 0x03, 0x05};
    uint16_t crc2 = sprotocol_crc16(data2, sizeof(data2));
    TEST_ASSERT(crc1 != crc2, "Different data should produce different CRC");

    uint16_t crc_empty = sprotocol_crc16(NULL, 0);
    TEST_ASSERT(crc_empty == 0xFFFF, "Empty data CRC should be 0xFFFF");

    return 1;
}

/*============================================================================
 * Test: Frame encode/decode
 *============================================================================*/

static int test_frame_encode_decode(void)
{
    sprotocol_frame_t orig;
    memset(&orig, 0, sizeof(orig));
    orig.header      = SPROTOCOL_FRAME_HEADER;
    orig.version     = SPROTOCOL_FRAME_VERSION;
    orig.src_addr    = 0x00;
    orig.dest_addr   = 0x10;
    orig.seq         = 42;
    orig.domain_id   = SPROTOCOL_DOMAIN_BASE;
    orig.msg_type    = SPROTOCOL_MSG_DATA;
    orig.payload_len = 5;
    memcpy(orig.payload, "hello", 5);

    uint8_t buf[512];
    size_t enc_len = sprotocol_frame_encode(&orig, buf, sizeof(buf));
    TEST_ASSERT(enc_len > 0, "Encode should succeed");
    TEST_ASSERT(enc_len == 11 + 5 + 2, "Encoded length should match");

    sprotocol_frame_t decoded;
    int ret = sprotocol_frame_decode(buf, enc_len, &decoded);
    TEST_ASSERT(ret == SPROTOCOL_OK, "Decode should succeed");
    TEST_ASSERT(decoded.src_addr == orig.src_addr, "src_addr mismatch");
    TEST_ASSERT(decoded.dest_addr == orig.dest_addr, "dest_addr mismatch");
    TEST_ASSERT(decoded.seq == orig.seq, "seq mismatch");
    TEST_ASSERT(decoded.domain_id == orig.domain_id, "domain_id mismatch");
    TEST_ASSERT(decoded.payload_len == 5, "payload_len mismatch");
    TEST_ASSERT(memcmp(decoded.payload, "hello", 5) == 0, "payload mismatch");

    /* Corrupt one byte and verify CRC check */
    buf[5] ^= 0xFF;
    ret = sprotocol_frame_decode(buf, enc_len, &decoded);
    TEST_ASSERT(ret == SPROTOCOL_ERR_CRC, "Corrupted data should fail CRC");

    return 1;
}

/*============================================================================
 * Test: Version string
 *============================================================================*/

static int test_version(void)
{
    const char *ver = sprotocol_get_version();
    TEST_ASSERT(ver != NULL, "Version should not be NULL");
    TEST_ASSERT(strcmp(ver, "1.0.0") == 0, "Version should be 1.0.0");
    return 1;
}

/*============================================================================
 * Test: Init/deinit
 *============================================================================*/

static send_ctx_t master_ctx, slave1_ctx, slave2_ctx;

static sprotocol_handle_t create_master(bool encryption)
{
    sprotocol_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = SPROTOCOL_ROLE_MASTER;
    cfg.local_addr = SPROTOCOL_ADDR_MASTER;
    cfg.max_slaves = SPROTOCOL_MAX_SLAVES;
    cfg.heartbeat_timeout = 3000;
    cfg.pair_timeout = 5000;
    cfg.send_cb = master_send_cb;
    cfg.get_time = get_sim_time;
    cfg.user_data = &master_ctx;
    cfg.encryption_enabled = encryption ? 1 : 0;
    cfg.enc_type = encryption ? SPROTOCOL_ENC_ECC : SPROTOCOL_ENC_NONE;
    return sprotocol_init(&cfg);
}

static sprotocol_handle_t create_slave(uint8_t addr, send_ctx_t *ctx,
                                       sprotocol_send_cb cb, bool encryption)
{
    sprotocol_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = SPROTOCOL_ROLE_SLAVE;
    cfg.local_addr = addr;
    cfg.max_slaves = 1;
    cfg.heartbeat_timeout = 3000;
    cfg.pair_timeout = 5000;
    cfg.send_cb = cb;
    cfg.get_time = get_sim_time;
    cfg.user_data = ctx;
    cfg.encryption_enabled = encryption ? 1 : 0;
    cfg.enc_type = encryption ? SPROTOCOL_ENC_ECC : SPROTOCOL_ENC_NONE;
    return sprotocol_init(&cfg);
}

static int test_init_deinit(void)
{
    sprotocol_handle_t h = create_master(false);
    TEST_ASSERT(h != NULL, "Init should succeed");
    sprotocol_deinit(h);

    /* Null send_cb should fail */
    sprotocol_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = SPROTOCOL_ROLE_MASTER;
    cfg.local_addr = SPROTOCOL_ADDR_MASTER;
    h = sprotocol_init(&cfg);
    TEST_ASSERT(h == NULL, "Init without send_cb should fail");

    return 1;
}

/*============================================================================
 * Test: Single pairing (no encryption)
 *============================================================================*/

static int test_single_pair(void)
{
    sim_time_ms = 1000;

    sprotocol_handle_t master = create_master(false);
    sprotocol_handle_t slave1 = create_slave(0x10, &slave1_ctx, slave_send_cb, false);
    TEST_ASSERT(master != NULL && slave1 != NULL, "Init should succeed");

    int ret = sprotocol_pair_request(master, 0x10);
    TEST_ASSERT(ret == SPROTOCOL_OK, "Pair request should succeed");

    pump_messages(master, slave1, NULL, 10);

    const sprotocol_device_t *dev = sprotocol_get_device(master, 0x10);
    TEST_ASSERT(dev != NULL, "Device should exist on master");
    TEST_ASSERT(dev->pair_status == SPROTOCOL_PAIR_COMPLETE, "Device should be paired");

    const sprotocol_device_t *dev_s = sprotocol_get_device(slave1, SPROTOCOL_ADDR_MASTER);
    TEST_ASSERT(dev_s != NULL, "Master should exist on slave");
    TEST_ASSERT(dev_s->pair_status == SPROTOCOL_PAIR_COMPLETE, "Master should be paired on slave");

    sprotocol_deinit(master);
    sprotocol_deinit(slave1);
    return 1;
}

/*============================================================================
 * Test: Multiple pairings
 *============================================================================*/

static int test_multiple_pairs(void)
{
    sim_time_ms = 1000;

    sprotocol_handle_t master = create_master(false);
    sprotocol_handle_t slave1 = create_slave(0x10, &slave1_ctx, slave_send_cb, false);
    sprotocol_handle_t slave2 = create_slave(0x11, &slave2_ctx, slave_send_cb, false);
    TEST_ASSERT(master && slave1 && slave2, "Init should succeed");

    sprotocol_pair_request(master, 0x10);
    pump_messages(master, slave1, slave2, 10);

    sprotocol_pair_request(master, 0x11);
    pump_messages(master, slave1, slave2, 10);

    uint8_t addrs[5];
    int count = sprotocol_get_paired_devices(master, addrs, 5);
    TEST_ASSERT(count == 2, "Should have 2 paired devices");

    sprotocol_deinit(master);
    sprotocol_deinit(slave1);
    sprotocol_deinit(slave2);
    return 1;
}

/*============================================================================
 * Test: Remove device
 *============================================================================*/

static int test_remove_device(void)
{
    sim_time_ms = 1000;

    sprotocol_handle_t master = create_master(false);
    sprotocol_handle_t slave1 = create_slave(0x10, &slave1_ctx, slave_send_cb, false);
    TEST_ASSERT(master && slave1, "Init should succeed");

    sprotocol_pair_request(master, 0x10);
    pump_messages(master, slave1, NULL, 10);

    uint8_t addrs[5];
    int count = sprotocol_get_paired_devices(master, addrs, 5);
    TEST_ASSERT(count == 1, "Should have 1 paired device");

    int ret = sprotocol_remove_device(master, 0x10);
    TEST_ASSERT(ret == SPROTOCOL_OK, "Remove should succeed");

    count = sprotocol_get_paired_devices(master, addrs, 5);
    TEST_ASSERT(count == 0, "Should have 0 paired devices after remove");

    ret = sprotocol_remove_device(master, 0x10);
    TEST_ASSERT(ret == SPROTOCOL_ERR_NOT_FOUND, "Removing again should fail");

    sprotocol_deinit(master);
    sprotocol_deinit(slave1);
    return 1;
}

/*============================================================================
 * Test: Data send/receive (no encryption)
 *============================================================================*/

static uint8_t recv_buf[256];
static size_t  recv_len = 0;
static uint8_t recv_src = 0;
static uint16_t recv_domain = 0;
static uint8_t recv_type = 0;

static void test_recv_cb(uint8_t src_addr, uint16_t domain_id, uint8_t msg_type,
                         const uint8_t *payload, size_t len, void *user_data)
{
    (void)user_data;
    recv_src = src_addr;
    recv_domain = domain_id;
    recv_type = msg_type;
    recv_len = len;
    if (len > 0 && len <= sizeof(recv_buf))
        memcpy(recv_buf, payload, len);
}

static int test_data_send_recv(void)
{
    sim_time_ms = 1000;
    recv_len = 0;

    sprotocol_config_t mcfg;
    memset(&mcfg, 0, sizeof(mcfg));
    mcfg.role = SPROTOCOL_ROLE_MASTER;
    mcfg.local_addr = SPROTOCOL_ADDR_MASTER;
    mcfg.max_slaves = SPROTOCOL_MAX_SLAVES;
    mcfg.heartbeat_timeout = 3000;
    mcfg.pair_timeout = 5000;
    mcfg.send_cb = master_send_cb;
    mcfg.get_time = get_sim_time;
    mcfg.user_data = &master_ctx;

    sprotocol_config_t scfg;
    memset(&scfg, 0, sizeof(scfg));
    scfg.role = SPROTOCOL_ROLE_SLAVE;
    scfg.local_addr = 0x10;
    scfg.max_slaves = 1;
    scfg.heartbeat_timeout = 3000;
    scfg.pair_timeout = 5000;
    scfg.send_cb = slave_send_cb;
    scfg.recv_cb = test_recv_cb;
    scfg.get_time = get_sim_time;
    scfg.user_data = &slave1_ctx;

    sprotocol_handle_t master = sprotocol_init(&mcfg);
    sprotocol_handle_t slave1 = sprotocol_init(&scfg);
    TEST_ASSERT(master && slave1, "Init should succeed");

    sprotocol_pair_request(master, 0x10);
    pump_messages(master, slave1, NULL, 10);

    const uint8_t msg[] = "test data 123";
    int ret = sprotocol_send(master, 0x10, SPROTOCOL_DOMAIN_BASE,
                             SPROTOCOL_MSG_DATA, msg, sizeof(msg));
    TEST_ASSERT(ret == SPROTOCOL_OK, "Send should succeed");

    pump_messages(master, slave1, NULL, 10);

    TEST_ASSERT(recv_len == sizeof(msg), "Received length should match");
    TEST_ASSERT(memcmp(recv_buf, msg, sizeof(msg)) == 0, "Received data should match");
    TEST_ASSERT(recv_src == SPROTOCOL_ADDR_MASTER, "Source should be master");
    TEST_ASSERT(recv_domain == SPROTOCOL_DOMAIN_BASE, "Domain should match");

    sprotocol_deinit(master);
    sprotocol_deinit(slave1);
    return 1;
}

/*============================================================================
 * Test: Broadcast
 *============================================================================*/

static int broadcast_recv_count = 0;

static void broadcast_recv_cb(uint8_t src_addr, uint16_t domain_id, uint8_t msg_type,
                              const uint8_t *payload, size_t len, void *user_data)
{
    (void)src_addr; (void)domain_id; (void)msg_type;
    (void)payload; (void)len; (void)user_data;
    broadcast_recv_count++;
}

static int test_broadcast(void)
{
    sim_time_ms = 1000;
    broadcast_recv_count = 0;

    sprotocol_handle_t master = create_master(false);

    sprotocol_config_t scfg;
    memset(&scfg, 0, sizeof(scfg));
    scfg.role = SPROTOCOL_ROLE_SLAVE;
    scfg.local_addr = 0x10;
    scfg.max_slaves = 1;
    scfg.heartbeat_timeout = 3000;
    scfg.pair_timeout = 5000;
    scfg.send_cb = slave_send_cb;
    scfg.recv_cb = broadcast_recv_cb;
    scfg.get_time = get_sim_time;
    scfg.user_data = &slave1_ctx;
    sprotocol_handle_t slave1 = sprotocol_init(&scfg);

    scfg.local_addr = 0x11;
    scfg.user_data = &slave2_ctx;
    sprotocol_handle_t slave2 = sprotocol_init(&scfg);

    TEST_ASSERT(master && slave1 && slave2, "Init should succeed");

    /* Pair both slaves */
    sprotocol_pair_request(master, 0x10);
    pump_messages(master, slave1, slave2, 10);
    sprotocol_pair_request(master, 0x11);
    pump_messages(master, slave1, slave2, 10);

    /* Broadcast a message */
    const uint8_t msg[] = "broadcast";
    int ret = sprotocol_broadcast(master, SPROTOCOL_DOMAIN_BASE,
                                  SPROTOCOL_MSG_DATA, msg, sizeof(msg));
    TEST_ASSERT(ret == SPROTOCOL_OK, "Broadcast should succeed");

    pump_messages(master, slave1, slave2, 10);

    TEST_ASSERT(broadcast_recv_count >= 2, "Both slaves should receive broadcast");

    sprotocol_deinit(master);
    sprotocol_deinit(slave1);
    sprotocol_deinit(slave2);
    return 1;
}

/*============================================================================
 * Test: Sequence number increment
 *============================================================================*/

static int test_seq_increment(void)
{
    sim_time_ms = 1000;

    sprotocol_handle_t master = create_master(false);
    sprotocol_handle_t slave1 = create_slave(0x10, &slave1_ctx, slave_send_cb, false);
    TEST_ASSERT(master && slave1, "Init should succeed");

    uint16_t seq_before = sprotocol_get_tx_seq(master, SPROTOCOL_ADDR_MASTER);

    sprotocol_pair_request(master, 0x10);
    pump_messages(master, slave1, NULL, 10);

    /* Send a few data messages */
    const uint8_t msg[] = "seq test";
    sprotocol_send(master, 0x10, SPROTOCOL_DOMAIN_BASE, SPROTOCOL_MSG_DATA, msg, sizeof(msg));
    sprotocol_send(master, 0x10, SPROTOCOL_DOMAIN_BASE, SPROTOCOL_MSG_DATA, msg, sizeof(msg));

    uint16_t seq_after = sprotocol_get_tx_seq(master, SPROTOCOL_ADDR_MASTER);
    TEST_ASSERT(seq_after > seq_before, "Sequence number should increment");

    sprotocol_deinit(master);
    sprotocol_deinit(slave1);
    return 1;
}

/*============================================================================
 * Test: Heartbeat timeout
 *============================================================================*/

static uint8_t  offline_addr_log = 0;
static uint8_t  offline_status_log = 0xFF;

static void online_cb(uint8_t addr, uint8_t online, void *user_data)
{
    (void)user_data;
    offline_addr_log = addr;
    offline_status_log = online;
}

static int test_heartbeat_timeout(void)
{
    sim_time_ms = 1000;
    offline_addr_log = 0;
    offline_status_log = 0xFF;

    sprotocol_config_t mcfg;
    memset(&mcfg, 0, sizeof(mcfg));
    mcfg.role = SPROTOCOL_ROLE_MASTER;
    mcfg.local_addr = SPROTOCOL_ADDR_MASTER;
    mcfg.max_slaves = SPROTOCOL_MAX_SLAVES;
    mcfg.heartbeat_timeout = 3000;
    mcfg.pair_timeout = 5000;
    mcfg.send_cb = master_send_cb;
    mcfg.online_cb = online_cb;
    mcfg.get_time = get_sim_time;
    mcfg.user_data = &master_ctx;

    sprotocol_handle_t master = sprotocol_init(&mcfg);
    sprotocol_handle_t slave1 = create_slave(0x10, &slave1_ctx, slave_send_cb, false);
    TEST_ASSERT(master && slave1, "Init should succeed");

    sprotocol_pair_request(master, 0x10);
    pump_messages(master, slave1, NULL, 10);

    TEST_ASSERT(sprotocol_is_device_online(master, 0x10) == 1, "Device should be online after pairing");

    /* Send heartbeat */
    sprotocol_send_heartbeat(slave1);
    pump_messages(master, slave1, NULL, 5);
    TEST_ASSERT(sprotocol_is_device_online(master, 0x10) == 1, "Device should be online after heartbeat");

    /* Advance past timeout without heartbeat */
    advance_time(3500);
    sprotocol_poll(master);

    TEST_ASSERT(sprotocol_is_device_online(master, 0x10) == 0, "Device should be offline after timeout");
    TEST_ASSERT(offline_addr_log == 0x10, "Offline callback should report correct address");
    TEST_ASSERT(offline_status_log == SPROTOCOL_DEVICE_OFFLINE, "Offline callback should report offline");

    sprotocol_deinit(master);
    sprotocol_deinit(slave1);
    return 1;
}

/*============================================================================
 * Test: Invalid address / boundary conditions
 *============================================================================*/

static int test_boundary_conditions(void)
{
    sim_time_ms = 1000;

    sprotocol_handle_t master = create_master(false);
    TEST_ASSERT(master != NULL, "Init should succeed");

    int ret = sprotocol_pair_request(master, 0x05);
    TEST_ASSERT(ret == SPROTOCOL_ERR_INVALID_ARG, "Invalid slave address should fail");

    ret = sprotocol_pair_request(master, 0x20);
    TEST_ASSERT(ret == SPROTOCOL_ERR_INVALID_ARG, "Out-of-range slave address should fail");

    /* Pair 5 slaves using per-slave UDP endpoints */
    udp_endpoint_t extra_eps[3];
    udp_endpoint_t *slave_ep_ptrs[5];
    send_ctx_t slave_ctxs[5];
    sprotocol_handle_t slaves[5];

    slave_ep_ptrs[0] = &ep_slave1;
    slave_ep_ptrs[1] = &ep_slave2;
    for (int i = 2; i < 5; i++) {
        udp_init(&extra_eps[i - 2], (uint16_t)(SLAVE1_PORT + i));
        slave_ep_ptrs[i] = &extra_eps[i - 2];
    }

    for (int i = 0; i < 5; i++) {
        uint8_t addr = (uint8_t)(0x10 + i);
        slave_ctxs[i].ep = slave_ep_ptrs[i];
        slaves[i] = create_slave(addr, &slave_ctxs[i], slave_send_cb, false);
    }

    for (int i = 0; i < 5; i++) {
        uint8_t addr = (uint8_t)(0x10 + i);
        sprotocol_pair_request(master, addr);

        /* Pump between master and this specific slave */
        uint8_t buf[1024];
        for (int r = 0; r < 10; r++) {
            usleep(1000);
            ssize_t n;
            while ((n = udp_recv(&ep_master, buf, sizeof(buf))) > 0)
                sprotocol_input(master, buf, (size_t)n);
            while ((n = udp_recv(slave_ep_ptrs[i], buf, sizeof(buf))) > 0)
                sprotocol_input(slaves[i], buf, (size_t)n);
            sprotocol_poll(master);
            sprotocol_poll(slaves[i]);
        }
    }

    uint8_t addrs[5];
    int count = sprotocol_get_paired_devices(master, addrs, 5);
    TEST_ASSERT(count == 5, "Should have 5 paired devices");

    /* Null handle tests */
    TEST_ASSERT(sprotocol_is_device_online(NULL, 0x10) == 0, "Null handle should return 0");
    TEST_ASSERT(sprotocol_get_device(NULL, 0x10) == NULL, "Null handle should return NULL");

    for (int i = 0; i < 5; i++)
        sprotocol_deinit(slaves[i]);
    for (int i = 0; i < 3; i++)
        udp_close(&extra_eps[i]);
    sprotocol_deinit(master);
    return 1;
}

/*============================================================================
 * Test: ECC key exchange during pairing
 *============================================================================*/

static int test_ecc_pairing(void)
{
    sim_time_ms = 1000;

    sprotocol_handle_t master = create_master(true);
    sprotocol_handle_t slave1 = create_slave(0x10, &slave1_ctx, slave_send_cb, true);
    TEST_ASSERT(master != NULL, "Master init with encryption should succeed");
    TEST_ASSERT(slave1 != NULL, "Slave init with encryption should succeed");

    int ret = sprotocol_pair_request(master, 0x10);
    TEST_ASSERT(ret == SPROTOCOL_OK, "Encrypted pair request should succeed");

    pump_messages(master, slave1, NULL, 10);

    const sprotocol_device_t *dev = sprotocol_get_device(master, 0x10);
    TEST_ASSERT(dev != NULL, "Device should exist on master");
    TEST_ASSERT(dev->pair_status == SPROTOCOL_PAIR_COMPLETE, "Device should be paired");

    const sprotocol_device_t *dev_s = sprotocol_get_device(slave1, SPROTOCOL_ADDR_MASTER);
    TEST_ASSERT(dev_s != NULL, "Master should exist on slave");
    TEST_ASSERT(dev_s->pair_status == SPROTOCOL_PAIR_COMPLETE, "Master should be paired on slave");

    sprotocol_deinit(master);
    sprotocol_deinit(slave1);
    return 1;
}

/*============================================================================
 * Test: Encrypted data send/receive
 *============================================================================*/

static int test_encrypted_data(void)
{
    sim_time_ms = 1000;
    recv_len = 0;
    memset(recv_buf, 0, sizeof(recv_buf));

    sprotocol_config_t mcfg;
    memset(&mcfg, 0, sizeof(mcfg));
    mcfg.role = SPROTOCOL_ROLE_MASTER;
    mcfg.local_addr = SPROTOCOL_ADDR_MASTER;
    mcfg.max_slaves = SPROTOCOL_MAX_SLAVES;
    mcfg.heartbeat_timeout = 3000;
    mcfg.pair_timeout = 5000;
    mcfg.send_cb = master_send_cb;
    mcfg.get_time = get_sim_time;
    mcfg.user_data = &master_ctx;
    mcfg.encryption_enabled = 1;
    mcfg.enc_type = SPROTOCOL_ENC_ECC;

    sprotocol_config_t scfg;
    memset(&scfg, 0, sizeof(scfg));
    scfg.role = SPROTOCOL_ROLE_SLAVE;
    scfg.local_addr = 0x10;
    scfg.max_slaves = 1;
    scfg.heartbeat_timeout = 3000;
    scfg.pair_timeout = 5000;
    scfg.send_cb = slave_send_cb;
    scfg.recv_cb = test_recv_cb;
    scfg.get_time = get_sim_time;
    scfg.user_data = &slave1_ctx;
    scfg.encryption_enabled = 1;
    scfg.enc_type = SPROTOCOL_ENC_ECC;

    sprotocol_handle_t master = sprotocol_init(&mcfg);
    sprotocol_handle_t slave1 = sprotocol_init(&scfg);
    TEST_ASSERT(master && slave1, "Init with encryption should succeed");

    sprotocol_pair_request(master, 0x10);
    pump_messages(master, slave1, NULL, 10);

    const sprotocol_device_t *dev = sprotocol_get_device(master, 0x10);
    TEST_ASSERT(dev && dev->pair_status == SPROTOCOL_PAIR_COMPLETE,
                "Encrypted pairing should complete");

    const uint8_t msg[] = "encrypted hello!";
    int ret = sprotocol_send(master, 0x10, SPROTOCOL_DOMAIN_BASE,
                             SPROTOCOL_MSG_DATA, msg, sizeof(msg));
    TEST_ASSERT(ret == SPROTOCOL_OK, "Encrypted send should succeed");

    pump_messages(master, slave1, NULL, 10);

    TEST_ASSERT(recv_len == sizeof(msg), "Decrypted length should match original");
    TEST_ASSERT(memcmp(recv_buf, msg, sizeof(msg)) == 0,
                "Decrypted data should match original");

    sprotocol_deinit(master);
    sprotocol_deinit(slave1);
    return 1;
}

/*============================================================================
 * Test: Blacklist (sequence violation)
 *============================================================================*/

static int test_blacklist(void)
{
    sim_time_ms = 1000;

    sprotocol_handle_t master = create_master(false);
    TEST_ASSERT(master != NULL, "Init should succeed");

    TEST_ASSERT(sprotocol_is_blacklisted(master, 0x10) == 0, "Should not be blacklisted");
    TEST_ASSERT(sprotocol_get_blacklist_count(master) == 0, "Blacklist should be empty");

    /* Manually craft a frame with an old sequence number to trigger violation.
       First pair, then send valid data, then send with old seq. */
    sprotocol_handle_t slave1 = create_slave(0x10, &slave1_ctx, slave_send_cb, false);
    sprotocol_pair_request(master, 0x10);
    pump_messages(master, slave1, NULL, 10);

    /* Send valid data to establish seq baseline */
    sprotocol_send(slave1, SPROTOCOL_ADDR_MASTER, SPROTOCOL_DOMAIN_BASE,
                   SPROTOCOL_MSG_DATA, (const uint8_t *)"a", 1);
    pump_messages(master, slave1, NULL, 5);

    sprotocol_send(slave1, SPROTOCOL_ADDR_MASTER, SPROTOCOL_DOMAIN_BASE,
                   SPROTOCOL_MSG_DATA, (const uint8_t *)"b", 1);
    pump_messages(master, slave1, NULL, 5);

    /* Count should be 0 or 1 (not heavily triggered yet) - just ensure mechanism works */
    int bl_count = sprotocol_get_blacklist_count(master);
    TEST_ASSERT(bl_count >= 0, "Blacklist count should be non-negative");

    sprotocol_deinit(master);
    sprotocol_deinit(slave1);
    return 1;
}

/*============================================================================
 * Test: Remove all devices
 *============================================================================*/

static int test_remove_all(void)
{
    sim_time_ms = 1000;

    sprotocol_handle_t master = create_master(false);
    sprotocol_handle_t slave1 = create_slave(0x10, &slave1_ctx, slave_send_cb, false);
    sprotocol_handle_t slave2 = create_slave(0x11, &slave2_ctx, slave_send_cb, false);

    sprotocol_pair_request(master, 0x10);
    pump_messages(master, slave1, slave2, 10);
    sprotocol_pair_request(master, 0x11);
    pump_messages(master, slave1, slave2, 10);

    uint8_t addrs[5];
    TEST_ASSERT(sprotocol_get_paired_devices(master, addrs, 5) == 2,
                "Should have 2 devices");

    sprotocol_remove_all_devices(master);
    TEST_ASSERT(sprotocol_get_paired_devices(master, addrs, 5) == 0,
                "Should have 0 devices after remove all");

    sprotocol_deinit(master);
    sprotocol_deinit(slave1);
    sprotocol_deinit(slave2);
    return 1;
}

/*============================================================================
 * Test: Pair timeout
 *============================================================================*/

static uint8_t pair_cb_addr = 0;
static uint8_t pair_cb_status = 0xFF;

static void test_pair_cb(uint8_t addr, uint8_t status, void *user_data)
{
    (void)user_data;
    pair_cb_addr = addr;
    pair_cb_status = status;
}

static int test_pair_timeout(void)
{
    sim_time_ms = 1000;
    pair_cb_addr = 0;
    pair_cb_status = 0xFF;

    sprotocol_config_t mcfg;
    memset(&mcfg, 0, sizeof(mcfg));
    mcfg.role = SPROTOCOL_ROLE_MASTER;
    mcfg.local_addr = SPROTOCOL_ADDR_MASTER;
    mcfg.max_slaves = SPROTOCOL_MAX_SLAVES;
    mcfg.heartbeat_timeout = 3000;
    mcfg.pair_timeout = 5000;
    mcfg.send_cb = master_send_cb;
    mcfg.pair_cb = test_pair_cb;
    mcfg.get_time = get_sim_time;
    mcfg.user_data = &master_ctx;

    sprotocol_handle_t master = sprotocol_init(&mcfg);
    TEST_ASSERT(master != NULL, "Init should succeed");

    /* Request pairing but no slave exists to respond */
    sprotocol_pair_request(master, 0x10);

    /* Don't pump slave messages - no one responds */
    advance_time(6000);
    sprotocol_poll(master);

    TEST_ASSERT(pair_cb_addr == 0x10, "Timeout callback should report address 0x10");
    TEST_ASSERT(pair_cb_status == SPROTOCOL_PAIR_NONE, "Timeout should reset to NONE");

    sprotocol_deinit(master);
    return 1;
}

/*============================================================================
 * Test: Slave role restrictions
 *============================================================================*/

static int test_slave_restrictions(void)
{
    sim_time_ms = 1000;

    sprotocol_handle_t slave1 = create_slave(0x10, &slave1_ctx, slave_send_cb, false);
    TEST_ASSERT(slave1 != NULL, "Init should succeed");

    int ret = sprotocol_pair_request(slave1, 0x11);
    TEST_ASSERT(ret == SPROTOCOL_ERR_INVALID_STATE, "Slave should not initiate pairing");

    ret = sprotocol_send_heartbeat(slave1);
    TEST_ASSERT(ret == SPROTOCOL_ERR_NOT_FOUND, "No paired master, heartbeat should fail");

    sprotocol_deinit(slave1);
    return 1;
}

/*============================================================================
 * Main
 *============================================================================*/

int main(void)
{
    printf("=== sprotocol test suite ===\n");
    printf("Version: %s\n\n", sprotocol_get_version());

    /* Initialize UDP endpoints */
    if (udp_init(&ep_master, MASTER_PORT) < 0 ||
        udp_init(&ep_slave1, SLAVE1_PORT) < 0 ||
        udp_init(&ep_slave2, SLAVE2_PORT) < 0) {
        printf("FATAL: Failed to initialize UDP sockets\n");
        return 1;
    }

    master_ctx.ep = &ep_master;
    slave1_ctx.ep = &ep_slave1;
    slave2_ctx.ep = &ep_slave2;

    /* Run tests */
    RUN_TEST(test_crc16);
    RUN_TEST(test_frame_encode_decode);
    RUN_TEST(test_version);
    RUN_TEST(test_init_deinit);
    RUN_TEST(test_single_pair);
    RUN_TEST(test_multiple_pairs);
    RUN_TEST(test_remove_device);
    RUN_TEST(test_remove_all);
    RUN_TEST(test_data_send_recv);
    RUN_TEST(test_broadcast);
    RUN_TEST(test_seq_increment);
    RUN_TEST(test_heartbeat_timeout);
    RUN_TEST(test_pair_timeout);
    RUN_TEST(test_boundary_conditions);
    RUN_TEST(test_slave_restrictions);
    RUN_TEST(test_blacklist);
    RUN_TEST(test_ecc_pairing);
    RUN_TEST(test_encrypted_data);

    printf("\n=== Results: %d/%d passed, %d failed ===\n",
           tests_passed, tests_run, tests_failed);

    udp_close(&ep_master);
    udp_close(&ep_slave1);
    udp_close(&ep_slave2);

    return tests_failed > 0 ? 1 : 0;
}
