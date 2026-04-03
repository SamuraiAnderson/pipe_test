#ifndef TEST_UDP_H
#define TEST_UDP_H

#include "sprotocol.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int id;
    int port;
    int sock;
    sprotocol_handle_t sp;
    sprotocol_config_t config;
    bool is_master;
    uint8_t addr;
    
    // Test verification flags
    bool paired;
    bool online;
    int received_msg_count;
    uint8_t last_recv_msg_type;
} udp_device_t;

// Initialize the UDP simulation environment
void udp_sim_init(void);

// Create a simulated device
udp_device_t* udp_sim_create_device(uint8_t addr, int port, bool is_master, bool enable_encryption);

// Destroy a simulated device
void udp_sim_destroy_device(udp_device_t* dev);

// Poll all devices (receive UDP packets and feed to sprotocol, then call sprotocol_poll)
void udp_sim_poll_all(void);

// Get current time in ms
uint32_t udp_sim_get_time(void);

#ifdef __cplusplus
}
#endif

#endif // TEST_UDP_H
