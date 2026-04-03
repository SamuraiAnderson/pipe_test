/**
 * @file device.c
 * @brief 设备管理模块
 */

#include "sprotocol.h"
#include "sprotocol_internal.h"
#include <string.h>

/* 获取设备索引 */
static int device_get_index(sprotocol_handle_t handle, uint8_t addr) {
    if (!handle) {
        return -1;
    }
    
    for (int i = 0; i < handle->config.max_slaves; i++) {
        if (handle->devices[i].addr == addr) {
            return i;
        }
    }
    
    return -1;
}

/* 查找空闲位置 */
static int device_find_free(sprotocol_handle_t handle) {
    if (!handle) {
        return -1;
    }
    
    for (int i = 0; i < handle->config.max_slaves; i++) {
        if (handle->devices[i].addr == 0) {
            return i;
        }
    }
    
    return -1;
}

sprotocol_device_t* device_get(sprotocol_handle_t handle, uint8_t addr) {
    int idx = device_get_index(handle, addr);
    if (idx < 0) {
        return NULL;
    }
    return &handle->devices[idx];
}

sprotocol_device_t* device_add(sprotocol_handle_t handle, uint8_t addr) {
    if (!handle) {
        return NULL;
    }
    
    /* 地址0是有效的（主机地址） */
    /* 检查是否已存在 */
    int idx = device_get_index(handle, addr);
    if (idx >= 0) {
        return &handle->devices[idx];
    }
    
    /* 查找空闲位置 */
    idx = device_find_free(handle);
    if (idx < 0) {
        return NULL;  /* 设备表已满 */
    }
    
    /* 初始化设备 */
    sprotocol_device_t* dev = &handle->devices[idx];
    dev->addr = addr;
    dev->pair_status = SPROTOCOL_PAIR_NONE;
    dev->online = SPROTOCOL_DEVICE_OFFLINE;
    dev->seq_tx = 0;
    dev->seq_rx = 0;
    dev->last_heartbeat = 0;
    dev->pair_time = 0;
    
    return dev;
}

void device_remove(sprotocol_handle_t handle, uint8_t addr) {
    int idx = device_get_index(handle, addr);
    if (idx < 0) {
        return;
    }
    
    memset(&handle->devices[idx], 0, sizeof(sprotocol_device_t));
}

void device_clear_all(sprotocol_handle_t handle) {
    if (!handle) {
        return;
    }
    
    for (int i = 0; i < handle->config.max_slaves; i++) {
        memset(&handle->devices[i], 0, sizeof(sprotocol_device_t));
    }
}

int device_get_list(sprotocol_handle_t handle, uint8_t* addrs, uint8_t max_count) {
    if (!handle || !addrs || max_count == 0) {
        return 0;
    }
    
    int count = 0;
    for (int i = 0; i < handle->config.max_slaves && count < max_count; i++) {
        if (handle->devices[i].addr != 0 &&
            handle->devices[i].pair_status == SPROTOCOL_PAIR_COMPLETE) {
            addrs[count++] = handle->devices[i].addr;
        }
    }
    
    return count;
}

/* 公开API实现 */
int sprotocol_remove_device(sprotocol_handle_t handle, uint8_t addr) {
    if (!handle) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }
    
    if (addr < SPROTOCOL_MIN_SLAVE_ADDR || addr > SPROTOCOL_MAX_SLAVE_ADDR) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }
    
    device_remove(handle, addr);
    return SPROTOCOL_OK;
}

void sprotocol_remove_all_devices(sprotocol_handle_t handle) {
    if (!handle) {
        return;
    }
    
    device_clear_all(handle);
}

int sprotocol_get_paired_devices(sprotocol_handle_t handle, uint8_t* addrs, uint8_t max_count) {
    if (!handle || !addrs) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }
    
    return device_get_list(handle, addrs, max_count);
}

const sprotocol_device_t* sprotocol_get_device(sprotocol_handle_t handle, uint8_t addr) {
    if (!handle) {
        return NULL;
    }
    
    return device_get(handle, addr);
}
