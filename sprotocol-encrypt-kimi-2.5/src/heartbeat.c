/**
 * @file heartbeat.c
 * @brief 心跳管理模块
 */

#include "sprotocol.h"
#include "sprotocol_internal.h"
#include <string.h>

int sprotocol_send_heartbeat(sprotocol_handle_t handle) {
    if (!handle) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }
    
    /* 只有从机发送心跳 */
    if (handle->config.role != SPROTOCOL_ROLE_SLAVE) {
        return SPROTOCOL_ERR_INVALID_STATE;
    }
    
    /* 查找配对的主机 */
    sprotocol_device_t* master = device_get(handle, SPROTOCOL_ADDR_MASTER);
    if (!master || master->pair_status != SPROTOCOL_PAIR_COMPLETE) {
        return SPROTOCOL_ERR_INVALID_STATE;
    }
    
    /* 构建心跳帧 */
    sprotocol_frame_t frame;
    memset(&frame, 0, sizeof(frame));
    
    frame.header = SPROTOCOL_FRAME_HEADER;
    frame.version = SPROTOCOL_FRAME_VERSION;
    frame.flags.need_ack = 0;
    frame.src_addr = handle->config.local_addr;
    frame.dest_addr = SPROTOCOL_ADDR_MASTER;
    frame.seq = seq_get_tx(handle, SPROTOCOL_ADDR_MASTER);
    frame.domain_id = SPROTOCOL_DOMAIN_BASE;
    frame.msg_type = SPROTOCOL_MSG_HEARTBEAT;
    frame.payload_len = 0;
    
    uint8_t buffer[64];
    size_t len;
    int ret = sprotocol_frame_pack(&frame, buffer, &len);
    if (ret == SPROTOCOL_OK) {
        handle->config.send_cb(buffer, len, handle->config.user_data);
    }
    
    return ret;
}

void heartbeat_handle(sprotocol_handle_t handle, const sprotocol_frame_t* frame) {
    if (!handle || !frame) {
        return;
    }
    
    uint32_t current_time = get_time_ms(handle);
    
    /* 获取或创建设备 */
    sprotocol_device_t* dev = device_get(handle, frame->src_addr);
    if (!dev) {
        dev = device_add(handle, frame->src_addr);
        if (!dev) {
            return;
        }
    }
    
    uint8_t was_online = dev->online;
    
    /* 更新心跳时间 */
    dev->last_heartbeat = current_time;
    dev->online = SPROTOCOL_DEVICE_ONLINE;
    
    /* 状态变化时通知 */
    if (!was_online && handle->config.online_cb) {
        handle->config.online_cb(frame->src_addr, SPROTOCOL_DEVICE_ONLINE, handle->config.user_data);
    }
}

void heartbeat_check_timeout(sprotocol_handle_t handle) {
    if (!handle) {
        return;
    }
    
    /* 只有主机检查从机心跳超时 */
    if (handle->config.role != SPROTOCOL_ROLE_MASTER) {
        return;
    }
    
    uint32_t current_time = get_time_ms(handle);
    
    for (int i = 0; i < handle->config.max_slaves; i++) {
        sprotocol_device_t* dev = &handle->devices[i];
        
        if (dev->addr == 0 || dev->pair_status != SPROTOCOL_PAIR_COMPLETE) {
            continue;
        }
        
        if (dev->online == SPROTOCOL_DEVICE_ONLINE) {
            uint32_t elapsed = current_time - dev->last_heartbeat;
            
            if (elapsed >= handle->config.heartbeat_timeout) {
                /* 心跳超时 */
                dev->online = SPROTOCOL_DEVICE_OFFLINE;
                
                /* 通知应用层 */
                if (handle->config.online_cb) {
                    handle->config.online_cb(dev->addr, SPROTOCOL_DEVICE_OFFLINE, handle->config.user_data);
                }
            }
        }
    }
}

int sprotocol_is_device_online(sprotocol_handle_t handle, uint8_t addr) {
    if (!handle) {
        return 0;
    }
    
    sprotocol_device_t* dev = device_get(handle, addr);
    if (!dev) {
        return 0;
    }
    
    return (dev->online == SPROTOCOL_DEVICE_ONLINE) ? 1 : 0;
}
