#include "sprotocol.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define TEST_MASTER_PORT 9000
#define TEST_SLAVE1_PORT 9001
#define TEST_SLAVE2_PORT 9002
#define TEST_MAX_FRAME_LEN 512

typedef struct test_bus test_bus_t;

typedef struct {
    const char* name;
    uint8_t addr;
    uint16_t port;
    int sock;
    test_bus_t* bus;
    sprotocol_handle_t handle;
    uint8_t flash[256];
    int recv_count;
    int pair_event_count;
    int online_event_count;
    uint8_t last_pair_addr;
    uint8_t last_pair_status;
    uint8_t last_online_addr;
    uint8_t last_online_status;
    uint8_t last_recv_src;
    uint16_t last_recv_domain;
    uint8_t last_recv_msg;
    uint8_t last_recv_payload[SPROTOCOL_MAX_PAYLOAD_LEN];
    size_t last_recv_len;
    uint8_t last_tx[TEST_MAX_FRAME_LEN];
    size_t last_tx_len;
} test_endpoint_t;

struct test_bus {
    uint32_t now_ms;
    test_endpoint_t* endpoints[3];
    size_t endpoint_count;
};

static test_bus_t* g_active_bus = NULL;

#define CHECK_TRUE(expr)                                                                 \
    do {                                                                                 \
        if (!(expr)) {                                                                   \
            fprintf(stderr, "CHECK failed: %s (%s:%d)\n", #expr, __FILE__, __LINE__);   \
            exit(1);                                                                     \
        }                                                                                \
    } while (0)

#define CHECK_EQ_INT(actual, expected)                                                   \
    do {                                                                                 \
        int actual_value__ = (actual);                                                   \
        int expected_value__ = (expected);                                               \
        if (actual_value__ != expected_value__) {                                        \
            fprintf(stderr,                                                               \
                    "CHECK failed: %s == %s (actual=%d expected=%d) at %s:%d\n",         \
                    #actual,                                                             \
                    #expected,                                                           \
                    actual_value__,                                                      \
                    expected_value__,                                                    \
                    __FILE__,                                                            \
                    __LINE__);                                                           \
            exit(1);                                                                     \
        }                                                                                \
    } while (0)

static uint32_t test_time_now(void)
{
    return g_active_bus != NULL ? g_active_bus->now_ms : 0U;
}

static int test_flash_read(uint32_t addr, uint8_t* data, size_t len, void* user_data)
{
    test_endpoint_t* endpoint = (test_endpoint_t*)user_data;

    if (addr + len > sizeof(endpoint->flash)) {
        return -1;
    }

    memcpy(data, &endpoint->flash[addr], len);
    return 0;
}

static int test_flash_write(uint32_t addr, const uint8_t* data, size_t len, void* user_data)
{
    test_endpoint_t* endpoint = (test_endpoint_t*)user_data;

    if (addr + len > sizeof(endpoint->flash)) {
        return -1;
    }

    memcpy(&endpoint->flash[addr], data, len);
    return 0;
}

static uint16_t test_port_for_addr(uint8_t addr)
{
    switch (addr) {
        case SPROTOCOL_ADDR_MASTER:
            return TEST_MASTER_PORT;
        case SPROTOCOL_MIN_SLAVE_ADDR:
            return TEST_SLAVE1_PORT;
        case (SPROTOCOL_MIN_SLAVE_ADDR + 1U):
            return TEST_SLAVE2_PORT;
        default:
            return 0U;
    }
}

static void test_send_frame(const uint8_t* data, size_t len, void* user_data)
{
    test_endpoint_t* endpoint = (test_endpoint_t*)user_data;
    struct sockaddr_in addr;
    uint8_t dest_addr;
    size_t i;

    CHECK_TRUE(len <= sizeof(endpoint->last_tx));
    memcpy(endpoint->last_tx, data, len);
    endpoint->last_tx_len = len;
    dest_addr = data[4];

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (dest_addr == SPROTOCOL_ADDR_BROADCAST) {
        for (i = 0; i < endpoint->bus->endpoint_count; ++i) {
            if (endpoint->bus->endpoints[i] == endpoint) {
                continue;
            }
            addr.sin_port = htons(endpoint->bus->endpoints[i]->port);
            CHECK_EQ_INT((int)sendto(endpoint->sock, data, len, 0, (struct sockaddr*)&addr, sizeof(addr)), (int)len);
        }
        return;
    }

    addr.sin_port = htons(test_port_for_addr(dest_addr));
    CHECK_TRUE(addr.sin_port != 0U);
    CHECK_EQ_INT((int)sendto(endpoint->sock, data, len, 0, (struct sockaddr*)&addr, sizeof(addr)), (int)len);
}

static void test_pair_event(uint8_t addr, uint8_t status, void* user_data)
{
    test_endpoint_t* endpoint = (test_endpoint_t*)user_data;

    endpoint->pair_event_count++;
    endpoint->last_pair_addr = addr;
    endpoint->last_pair_status = status;
}

static void test_online_event(uint8_t addr, uint8_t online, void* user_data)
{
    test_endpoint_t* endpoint = (test_endpoint_t*)user_data;

    endpoint->online_event_count++;
    endpoint->last_online_addr = addr;
    endpoint->last_online_status = online;
}

static void test_recv_event(uint8_t src_addr,
                            uint16_t domain_id,
                            uint8_t msg_type,
                            const uint8_t* payload,
                            size_t len,
                            void* user_data)
{
    test_endpoint_t* endpoint = (test_endpoint_t*)user_data;

    endpoint->recv_count++;
    endpoint->last_recv_src = src_addr;
    endpoint->last_recv_domain = domain_id;
    endpoint->last_recv_msg = msg_type;
    endpoint->last_recv_len = len;
    if (len > 0U) {
        memcpy(endpoint->last_recv_payload, payload, len);
    }
}

static int test_make_socket(uint16_t port)
{
    int sock;
    struct sockaddr_in addr;
    int yes = 1;
    int flags;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK_TRUE(sock >= 0);
    CHECK_EQ_INT(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)), 0);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK_EQ_INT(bind(sock, (struct sockaddr*)&addr, sizeof(addr)), 0);

    flags = fcntl(sock, F_GETFL, 0);
    CHECK_TRUE(flags >= 0);
    CHECK_EQ_INT(fcntl(sock, F_SETFL, flags | O_NONBLOCK), 0);
    return sock;
}

static void test_bus_init(test_bus_t* bus)
{
    memset(bus, 0, sizeof(*bus));
    g_active_bus = bus;
}

static void test_bus_add_endpoint(test_bus_t* bus, test_endpoint_t* endpoint)
{
    CHECK_TRUE(bus->endpoint_count < 3U);
    bus->endpoints[bus->endpoint_count++] = endpoint;
}

static void test_endpoint_reset_observation(test_endpoint_t* endpoint)
{
    endpoint->recv_count = 0;
    endpoint->pair_event_count = 0;
    endpoint->online_event_count = 0;
    endpoint->last_pair_addr = 0;
    endpoint->last_pair_status = 0;
    endpoint->last_online_addr = 0;
    endpoint->last_online_status = 0;
    endpoint->last_recv_src = 0;
    endpoint->last_recv_domain = 0;
    endpoint->last_recv_msg = 0;
    endpoint->last_recv_len = 0;
    memset(endpoint->last_recv_payload, 0, sizeof(endpoint->last_recv_payload));
    endpoint->last_tx_len = 0;
    memset(endpoint->last_tx, 0, sizeof(endpoint->last_tx));
}

static void test_endpoint_init(test_endpoint_t* endpoint,
                               test_bus_t* bus,
                               const char* name,
                               sprotocol_role_t role,
                               uint8_t addr,
                               uint16_t port,
                               bool enable_encryption,
                               uint8_t max_slaves)
{
    sprotocol_config_t config;

    memset(endpoint, 0, sizeof(*endpoint));
    endpoint->name = name;
    endpoint->addr = addr;
    endpoint->port = port;
    endpoint->bus = bus;
    endpoint->sock = test_make_socket(port);
    test_endpoint_reset_observation(endpoint);

    memset(&config, 0, sizeof(config));
    config.role = role;
    config.local_addr = addr;
    config.max_slaves = max_slaves;
    config.heartbeat_timeout = 3000U;
    config.pair_timeout = 5000U;
    config.seq_save_interval = 1000U;
    config.encryption_enabled = enable_encryption ? 1U : 0U;
    config.enc_type = enable_encryption ? SPROTOCOL_ENC_ECC : SPROTOCOL_ENC_NONE;
    config.send_cb = test_send_frame;
    config.pair_cb = test_pair_event;
    config.online_cb = test_online_event;
    config.recv_cb = test_recv_event;
    config.flash_read = test_flash_read;
    config.flash_write = test_flash_write;
    config.get_time = test_time_now;
    config.user_data = endpoint;

    endpoint->handle = sprotocol_init(&config);
    CHECK_TRUE(endpoint->handle != NULL);
    test_bus_add_endpoint(bus, endpoint);
}

static void test_endpoint_deinit(test_endpoint_t* endpoint)
{
    if (endpoint->handle != NULL) {
        sprotocol_deinit(endpoint->handle);
        endpoint->handle = NULL;
    }
    if (endpoint->sock >= 0) {
        close(endpoint->sock);
        endpoint->sock = -1;
    }
}

static void test_bus_cleanup(test_bus_t* bus)
{
    size_t i;

    for (i = 0; i < bus->endpoint_count; ++i) {
        test_endpoint_deinit(bus->endpoints[i]);
    }
    g_active_bus = NULL;
}

static int test_endpoint_pump(test_endpoint_t* endpoint)
{
    uint8_t buffer[TEST_MAX_FRAME_LEN];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    ssize_t received;
    int count = 0;

    while (true) {
        received = recvfrom(endpoint->sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&from, &from_len);
        if (received < 0) {
            CHECK_TRUE(errno == EAGAIN || errno == EWOULDBLOCK);
            break;
        }
        sprotocol_input(endpoint->handle, buffer, (size_t)received);
        count++;
        from_len = sizeof(from);
    }

    sprotocol_poll(endpoint->handle);
    return count;
}

static void test_bus_drive(test_bus_t* bus, int max_rounds)
{
    int round;
    int idle_rounds = 0;

    for (round = 0; round < max_rounds; ++round) {
        int processed = 0;
        size_t i;

        for (i = 0; i < bus->endpoint_count; ++i) {
            processed += test_endpoint_pump(bus->endpoints[i]);
        }

        if (processed == 0) {
            ++idle_rounds;
            if (idle_rounds >= 2) {
                break;
            }
            usleep(1000);
        } else {
            idle_rounds = 0;
        }
    }
}

static void test_bus_advance(test_bus_t* bus, uint32_t delta_ms)
{
    bus->now_ms += delta_ms;
    test_bus_drive(bus, 4);
}

static void test_crc16_vector(void)
{
    const uint8_t vector[] = "123456789";
    CHECK_EQ_INT((int)sprotocol_crc16(vector, 9U), 0x29B1);
}

static void test_pair_send_broadcast_remove(void)
{
    test_bus_t bus;
    test_endpoint_t master;
    test_endpoint_t slave1;
    test_endpoint_t slave2;
    uint8_t addrs[SPROTOCOL_MAX_SLAVES];
    static const uint8_t ping[] = "ping";
    static const uint8_t hello[] = "hello";

    test_bus_init(&bus);
    test_endpoint_init(&master, &bus, "master", SPROTOCOL_ROLE_MASTER, SPROTOCOL_ADDR_MASTER, TEST_MASTER_PORT, false, 5U);
    test_endpoint_init(&slave1, &bus, "slave1", SPROTOCOL_ROLE_SLAVE, SPROTOCOL_MIN_SLAVE_ADDR, TEST_SLAVE1_PORT, false, 1U);
    test_endpoint_init(&slave2, &bus, "slave2", SPROTOCOL_ROLE_SLAVE, SPROTOCOL_MIN_SLAVE_ADDR + 1U, TEST_SLAVE2_PORT, false, 1U);

    CHECK_EQ_INT(sprotocol_pair_request(master.handle, slave1.addr), SPROTOCOL_OK);
    test_bus_drive(&bus, 16);
    CHECK_TRUE(slave1.last_tx_len > 0U);
    CHECK_EQ_INT(slave1.last_tx[9], SPROTOCOL_MSG_PAIR_RSP);
    CHECK_TRUE(master.last_tx_len > 0U);
    CHECK_EQ_INT(master.last_tx[9], SPROTOCOL_MSG_PAIR_CFM);
    CHECK_TRUE(sprotocol_get_device(master.handle, slave1.addr) != NULL);
    CHECK_EQ_INT(sprotocol_get_device(master.handle, slave1.addr)->pair_status, SPROTOCOL_PAIR_COMPLETE);
    CHECK_EQ_INT(sprotocol_pair_request(master.handle, slave2.addr), SPROTOCOL_OK);
    test_bus_drive(&bus, 16);

    CHECK_TRUE(sprotocol_get_device(master.handle, slave1.addr) != NULL);
    CHECK_EQ_INT(sprotocol_get_device(master.handle, slave1.addr)->pair_status, SPROTOCOL_PAIR_COMPLETE);
    CHECK_TRUE(sprotocol_get_device(slave1.handle, SPROTOCOL_ADDR_MASTER) != NULL);
    CHECK_EQ_INT(sprotocol_get_device(slave1.handle, SPROTOCOL_ADDR_MASTER)->pair_status, SPROTOCOL_PAIR_COMPLETE);
    CHECK_EQ_INT(sprotocol_get_paired_devices(master.handle, addrs, SPROTOCOL_MAX_SLAVES), 2);

    CHECK_EQ_INT(sprotocol_send(master.handle, slave1.addr, SPROTOCOL_DOMAIN_BASE, SPROTOCOL_MSG_DATA, ping, sizeof(ping) - 1U), SPROTOCOL_OK);
    test_bus_drive(&bus, 8);
    CHECK_EQ_INT(slave1.recv_count, 1);
    CHECK_EQ_INT((int)slave1.last_recv_len, (int)(sizeof(ping) - 1U));
    CHECK_TRUE(memcmp(slave1.last_recv_payload, ping, sizeof(ping) - 1U) == 0);

    test_endpoint_reset_observation(&slave1);
    test_endpoint_reset_observation(&slave2);
    CHECK_EQ_INT(sprotocol_broadcast(master.handle, SPROTOCOL_DOMAIN_OTA, SPROTOCOL_MSG_DATA, hello, sizeof(hello) - 1U), SPROTOCOL_OK);
    test_bus_drive(&bus, 8);
    CHECK_EQ_INT(slave1.recv_count, 1);
    CHECK_EQ_INT(slave2.recv_count, 1);
    CHECK_EQ_INT((int)slave1.last_recv_domain, SPROTOCOL_DOMAIN_OTA);

    CHECK_EQ_INT(sprotocol_remove_device(master.handle, slave2.addr), SPROTOCOL_OK);
    CHECK_TRUE(sprotocol_get_device(master.handle, slave2.addr) == NULL);
    CHECK_EQ_INT(sprotocol_get_paired_devices(master.handle, addrs, SPROTOCOL_MAX_SLAVES), 1);

    test_bus_cleanup(&bus);
}

static void test_pair_timeout_and_heartbeat_timeout(void)
{
    test_bus_t bus;
    test_endpoint_t master;
    test_endpoint_t slave1;

    test_bus_init(&bus);
    test_endpoint_init(&master, &bus, "master", SPROTOCOL_ROLE_MASTER, SPROTOCOL_ADDR_MASTER, TEST_MASTER_PORT, false, 5U);

    CHECK_EQ_INT(sprotocol_pair_request(master.handle, SPROTOCOL_MIN_SLAVE_ADDR), SPROTOCOL_OK);
    test_bus_advance(&bus, 5001U);
    CHECK_TRUE(sprotocol_get_device(master.handle, SPROTOCOL_MIN_SLAVE_ADDR) == NULL);

    test_bus_cleanup(&bus);

    test_bus_init(&bus);
    test_endpoint_init(&master, &bus, "master", SPROTOCOL_ROLE_MASTER, SPROTOCOL_ADDR_MASTER, TEST_MASTER_PORT, false, 5U);
    test_endpoint_init(&slave1, &bus, "slave1", SPROTOCOL_ROLE_SLAVE, SPROTOCOL_MIN_SLAVE_ADDR, TEST_SLAVE1_PORT, false, 1U);

    CHECK_EQ_INT(sprotocol_pair_request(master.handle, slave1.addr), SPROTOCOL_OK);
    test_bus_drive(&bus, 16);

    CHECK_EQ_INT(sprotocol_send_heartbeat(slave1.handle), SPROTOCOL_OK);
    test_bus_drive(&bus, 8);
    CHECK_EQ_INT(sprotocol_is_device_online(master.handle, slave1.addr), 1);

    test_bus_advance(&bus, 3001U);
    CHECK_EQ_INT(sprotocol_is_device_online(master.handle, slave1.addr), 0);
    CHECK_EQ_INT(master.last_online_status, SPROTOCOL_DEVICE_OFFLINE);

    test_bus_cleanup(&bus);
}

static void test_sequence_replay_blacklist(void)
{
    test_bus_t bus;
    test_endpoint_t master;
    test_endpoint_t slave1;
    int i;

    test_bus_init(&bus);
    test_endpoint_init(&master, &bus, "master", SPROTOCOL_ROLE_MASTER, SPROTOCOL_ADDR_MASTER, TEST_MASTER_PORT, false, 5U);
    test_endpoint_init(&slave1, &bus, "slave1", SPROTOCOL_ROLE_SLAVE, SPROTOCOL_MIN_SLAVE_ADDR, TEST_SLAVE1_PORT, false, 1U);

    CHECK_EQ_INT(sprotocol_pair_request(master.handle, slave1.addr), SPROTOCOL_OK);
    test_bus_drive(&bus, 16);

    CHECK_EQ_INT(sprotocol_send_heartbeat(slave1.handle), SPROTOCOL_OK);
    test_bus_drive(&bus, 8);
    CHECK_TRUE(slave1.last_tx_len > 0U);

    for (i = 0; i < SPROTOCOL_BLACKLIST_LIMIT; ++i) {
        sprotocol_input(master.handle, slave1.last_tx, slave1.last_tx_len);
    }

    CHECK_EQ_INT(sprotocol_is_blacklisted(master.handle, slave1.addr), 1);
    CHECK_EQ_INT(sprotocol_get_blacklist_count(master.handle), 1);

    test_bus_cleanup(&bus);
}

static void test_encrypted_pair_and_data(void)
{
    test_bus_t bus;
    test_endpoint_t master;
    test_endpoint_t slave1;
    static const uint8_t secure_payload[] = "secure-message";

    test_bus_init(&bus);
    test_endpoint_init(&master, &bus, "master", SPROTOCOL_ROLE_MASTER, SPROTOCOL_ADDR_MASTER, TEST_MASTER_PORT, true, 5U);
    test_endpoint_init(&slave1, &bus, "slave1", SPROTOCOL_ROLE_SLAVE, SPROTOCOL_MIN_SLAVE_ADDR, TEST_SLAVE1_PORT, true, 1U);

    CHECK_EQ_INT(sprotocol_pair_request(master.handle, slave1.addr), SPROTOCOL_OK);
    test_bus_drive(&bus, 24);

    CHECK_EQ_INT(sprotocol_send(master.handle,
                                slave1.addr,
                                SPROTOCOL_DOMAIN_BASE,
                                SPROTOCOL_MSG_DATA,
                                secure_payload,
                                sizeof(secure_payload) - 1U),
                 SPROTOCOL_OK);
    test_bus_drive(&bus, 8);

    CHECK_EQ_INT(slave1.recv_count, 1);
    CHECK_TRUE(memcmp(slave1.last_recv_payload, secure_payload, sizeof(secure_payload) - 1U) == 0);
    CHECK_TRUE(master.last_tx_len > 0U);
    CHECK_TRUE(memchr(master.last_tx, 's', master.last_tx_len) == NULL);
    CHECK_TRUE((master.last_tx[2] & (1U << 2)) != 0U);

    test_bus_cleanup(&bus);
}

int main(void)
{
    test_crc16_vector();
    test_pair_send_broadcast_remove();
    test_pair_timeout_and_heartbeat_timeout();
    test_sequence_replay_blacklist();
    test_encrypted_pair_and_data();
    printf("All sprotocol tests passed.\n");
    return 0;
}
