#include "test_udp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <errno.h>

#define MAX_DEVICES 10
#define FLASH_SIZE 4096

static udp_device_t* g_devices[MAX_DEVICES];
static int g_num_devices = 0;
static uint8_t g_flash_mem[MAX_DEVICES][FLASH_SIZE];

void udp_sim_init(void) {
    g_num_devices = 0;
    memset(g_devices, 0, sizeof(g_devices));
    memset(g_flash_mem, 0, sizeof(g_flash_mem));
}

uint32_t udp_sim_get_time(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint32_t)(tv.tv_sec * 1000 + tv.tv_usec / 1000);
}

static void my_send_cb(const uint8_t* data, size_t len, void* user_data) {
    udp_device_t* dev = (udp_device_t*)user_data;
    
    // Simulate RF broadcast by sending to all other devices via UDP
    for (int i = 0; i < g_num_devices; ++i) {
        if (g_devices[i] != dev) {
            struct sockaddr_in dest_addr;
            memset(&dest_addr, 0, sizeof(dest_addr));
            dest_addr.sin_family = AF_INET;
            dest_addr.sin_port = htons(g_devices[i]->port);
            dest_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
            
            sendto(dev->sock, data, len, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
        }
    }
}

static void my_pair_cb(uint8_t addr, uint8_t status, void* user_data) {
    udp_device_t* dev = (udp_device_t*)user_data;
    printf("[Device %02X] Pair status with %02X: %d\n", dev->addr, addr, status);
    if (status == SPROTOCOL_PAIR_COMPLETE) {
        dev->paired = true;
    }
}

static void my_online_cb(uint8_t addr, uint8_t online, void* user_data) {
    udp_device_t* dev = (udp_device_t*)user_data;
    printf("[Device %02X] Device %02X online status: %d\n", dev->addr, addr, online);
    if (online) {
        dev->online = true;
    } else {
        dev->online = false;
    }
}

static void my_recv_cb(uint8_t src_addr, uint16_t domain_id, uint8_t msg_type, const uint8_t* payload, size_t len, void* user_data) {
    (void)payload;
    udp_device_t* dev = (udp_device_t*)user_data;
    printf("[Device %02X] Received msg from %02X, domain: %d, type: %02X, len: %zu\n", 
           dev->addr, src_addr, domain_id, msg_type, len);
    dev->received_msg_count++;
    dev->last_recv_msg_type = msg_type;
}

static int my_flash_read(uint32_t addr, uint8_t* data, size_t len, void* user_data) {
    udp_device_t* dev = (udp_device_t*)user_data;
    if (addr + len > FLASH_SIZE) return -1;
    memcpy(data, &g_flash_mem[dev->id][addr], len);
    return 0;
}

static int my_flash_write(uint32_t addr, const uint8_t* data, size_t len, void* user_data) {
    udp_device_t* dev = (udp_device_t*)user_data;
    if (addr + len > FLASH_SIZE) return -1;
    memcpy(&g_flash_mem[dev->id][addr], data, len);
    return 0;
}

udp_device_t* udp_sim_create_device(uint8_t addr, int port, bool is_master, bool enable_encryption) {
    if (g_num_devices >= MAX_DEVICES) return NULL;
    
    udp_device_t* dev = (udp_device_t*)malloc(sizeof(udp_device_t));
    if (!dev) return NULL;
    
    memset(dev, 0, sizeof(udp_device_t));
    dev->id = g_num_devices;
    dev->port = port;
    dev->addr = addr;
    dev->is_master = is_master;
    
    // Create UDP socket
    dev->sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (dev->sock < 0) {
        free(dev);
        return NULL;
    }
    
    // Set non-blocking
    int flags = fcntl(dev->sock, F_GETFL, 0);
    fcntl(dev->sock, F_SETFL, flags | O_NONBLOCK);
    
    // Bind
    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(port);
    bind_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    
    if (bind(dev->sock, (struct sockaddr*)&bind_addr, sizeof(bind_addr)) < 0) {
        close(dev->sock);
        free(dev);
        return NULL;
    }
    
    // Configure S-Protocol
    dev->config.role = is_master ? SPROTOCOL_ROLE_MASTER : SPROTOCOL_ROLE_SLAVE;
    dev->config.local_addr = addr;
    dev->config.max_slaves = SPROTOCOL_MAX_SLAVES;
    dev->config.heartbeat_timeout = 3000;
    dev->config.pair_timeout = 5000;
    dev->config.seq_save_interval = 1000;
    dev->config.seq_check_interval = 500;
    
    dev->config.encryption_enabled = enable_encryption ? 1 : 0;
    dev->config.enc_type = SPROTOCOL_ENC_ECC;
    
    dev->config.send_cb = my_send_cb;
    dev->config.pair_cb = my_pair_cb;
    dev->config.online_cb = my_online_cb;
    dev->config.recv_cb = my_recv_cb;
    dev->config.flash_read = my_flash_read;
    dev->config.flash_write = my_flash_write;
    dev->config.get_time = udp_sim_get_time;
    dev->config.user_data = dev;
    
    dev->sp = sprotocol_init(&dev->config);
    if (!dev->sp) {
        close(dev->sock);
        free(dev);
        return NULL;
    }
    
    g_devices[g_num_devices++] = dev;
    return dev;
}

void udp_sim_destroy_device(udp_device_t* dev) {
    if (!dev) return;
    
    if (dev->sp) {
        sprotocol_deinit(dev->sp);
    }
    if (dev->sock >= 0) {
        close(dev->sock);
    }
    
    for (int i = 0; i < g_num_devices; ++i) {
        if (g_devices[i] == dev) {
            for (int j = i; j < g_num_devices - 1; ++j) {
                g_devices[j] = g_devices[j + 1];
            }
            g_num_devices--;
            break;
        }
    }
    
    free(dev);
}

void udp_sim_poll_all(void) {
    uint8_t buf[2048];
    for (int i = 0; i < g_num_devices; ++i) {
        udp_device_t* dev = g_devices[i];
        
        // Receive UDP packets
        while (1) {
            struct sockaddr_in src_addr;
            socklen_t src_len = sizeof(src_addr);
            ssize_t len = recvfrom(dev->sock, buf, sizeof(buf), 0, (struct sockaddr*)&src_addr, &src_len);
            if (len > 0) {
                sprotocol_input(dev->sp, buf, len);
            } else {
                break;
            }
        }
        
        // Poll protocol
        sprotocol_poll(dev->sp);
    }
}
