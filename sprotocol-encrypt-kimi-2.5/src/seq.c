/**
 * @file seq.c
 * @brief 序列号管理模块
 */

#include "sprotocol.h"
#include "sprotocol_internal.h"
#include <string.h>

void seq_init(sprotocol_handle_t handle) {
    if (!handle) {
        return;
    }
    
    /* 初始化序列号 */
    for (int i = 0; i < handle->config.max_slaves; i++) {
        handle->devices[i].seq_tx = 0;
        handle->devices[i].seq_rx = 0;
    }
    
    handle->seq_state.last_save_time = 0;
}

uint16_t seq_get_tx(sprotocol_handle_t handle, uint8_t addr) {
    if (!handle) {
        return 0;
    }
    
    sprotocol_device_t* dev = device_get(handle, addr);
    if (!dev) {
        return 0;
    }
    
    return dev->seq_tx++;
}

void seq_update_rx(sprotocol_handle_t handle, uint8_t addr, uint16_t seq) {
    if (!handle) {
        return;
    }
    
    sprotocol_device_t* dev = device_get(handle, addr);
    if (!dev) {
        return;
    }
    
    /* 序列号回绕检测 */
    if (seq < dev->seq_rx && (dev->seq_rx - seq) > 0x8000) {
        /* 正常的回绕 */
    } else if (seq <= dev->seq_rx) {
        /* 重复或乱序的序列号 - 可以记录异常 */
    }
    
    dev->seq_rx = seq;
}

void seq_save_periodic(sprotocol_handle_t handle) {
    if (!handle) {
        return;
    }
    
    uint32_t current_time = get_time_ms(handle);
    uint32_t elapsed = current_time - handle->seq_state.last_save_time;
    
    if (elapsed >= handle->config.seq_save_interval) {
        /* TODO: 保存序列号到Flash */
        handle->seq_state.last_save_time = current_time;
    }
}

uint16_t sprotocol_get_tx_seq(sprotocol_handle_t handle, uint8_t addr) {
    if (!handle) {
        return 0;
    }
    
    sprotocol_device_t* dev = device_get(handle, addr);
    if (!dev) {
        return 0;
    }
    
    return dev->seq_tx;
}

void sprotocol_set_seq_save_interval(sprotocol_handle_t handle, uint16_t interval_ms) {
    if (!handle) {
        return;
    }
    
    handle->config.seq_save_interval = interval_ms;
}
