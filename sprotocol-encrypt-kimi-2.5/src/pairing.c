/**
 * @file pairing.c
 * @brief 配对管理模块
 */

#include "sprotocol.h"
#include "sprotocol_internal.h"
#include <string.h>
#include <stdio.h>

/* 序列号获取辅助函数 */
extern uint16_t seq_get_next(sprotocol_handle_t handle, uint8_t addr);

static void send_pair_frame(sprotocol_handle_t handle, uint8_t dest_addr, 
                             uint8_t msg_type, const uint8_t* payload, uint8_t payload_len) {
    sprotocol_frame_t frame;
    memset(&frame, 0, sizeof(frame));
    
    frame.header = SPROTOCOL_FRAME_HEADER;
    frame.version = SPROTOCOL_FRAME_VERSION;
    frame.flags.need_ack = 0;
    frame.src_addr = handle->config.local_addr;
    frame.dest_addr = dest_addr;
    frame.seq = seq_get_tx(handle, dest_addr);
    frame.domain_id = SPROTOCOL_DOMAIN_BASE;
    frame.msg_type = msg_type;
    frame.payload_len = payload_len;
    
    if (payload_len > 0 && payload) {
        memcpy(frame.payload, payload, payload_len);
    }
    
    uint8_t buffer[512];
    size_t len;
    int ret = sprotocol_frame_pack(&frame, buffer, &len);
    if (ret == SPROTOCOL_OK) {
        handle->config.send_cb(buffer, len, handle->config.user_data);
    }
}

int sprotocol_pair_request(sprotocol_handle_t handle, uint8_t slave_addr) {
    if (!handle) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }
    
    if (handle->config.role != SPROTOCOL_ROLE_MASTER) {
        return SPROTOCOL_ERR_INVALID_STATE;
    }
    
    if (slave_addr < SPROTOCOL_MIN_SLAVE_ADDR || slave_addr > SPROTOCOL_MAX_SLAVE_ADDR) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }
    
    /* 检查是否已有活跃配对 */
    if (handle->pairing_state.active) {
        return SPROTOCOL_ERR_BUSY;
    }
    
    /* 添加或获取设备 */
    sprotocol_device_t* dev = device_get(handle, slave_addr);
    if (!dev) {
        dev = device_add(handle, slave_addr);
        if (!dev) {
            return SPROTOCOL_ERR_FULL;
        }
    }
    
    /* 更新设备状态为配对中 */
    dev->pair_status = SPROTOCOL_PAIR_PENDING;
    
    /* 设置配对状态 */
    handle->pairing_state.active = 1;
    handle->pairing_state.slave_addr = slave_addr;
    handle->pairing_state.start_time = get_time_ms(handle);
    
    /* 发送配对请求 */
    send_pair_frame(handle, slave_addr, SPROTOCOL_MSG_PAIR_REQ, NULL, 0);
    
    return SPROTOCOL_OK;
}

void pairing_handle_request(sprotocol_handle_t handle, const sprotocol_frame_t* frame) {
    if (!handle || !frame) {
        return;
    }
    
    /* 只有从机响应配对请求 */
    if (handle->config.role != SPROTOCOL_ROLE_SLAVE) {
        return;
    }
    
    /* 验证源地址是主机 */
    if (frame->src_addr != SPROTOCOL_ADDR_MASTER) {
        return;
    }
    
    /* 添加主机设备 */
    sprotocol_device_t* dev = device_get(handle, frame->src_addr);
    if (!dev) {
        dev = device_add(handle, frame->src_addr);
        if (!dev) {
            return;
        }
    }
    
    /* 更新配对状态 */
    dev->pair_status = SPROTOCOL_PAIR_PENDING;
    dev->pair_time = get_time_ms(handle);
    
    /* 发送配对响应 */
    send_pair_frame(handle, frame->src_addr, SPROTOCOL_MSG_PAIR_RSP, NULL, 0);
}

void pairing_handle_response(sprotocol_handle_t handle, const sprotocol_frame_t* frame) {
    if (!handle || !frame) {
        return;
    }
    
    /* 只有主机处理配对响应 */
    if (handle->config.role != SPROTOCOL_ROLE_MASTER) {
        return;
    }
    
    /* 检查是否有活跃的配对请求 */
    if (!handle->pairing_state.active) {
        return;
    }
    
    /* 验证地址 */
    if (frame->src_addr != handle->pairing_state.slave_addr) {
        return;
    }
    
    /* 获取设备 */
    sprotocol_device_t* dev = device_get(handle, frame->src_addr);
    if (!dev) {
        return;
    }
    
    /* 更新设备状态 */
    dev->pair_status = SPROTOCOL_PAIR_COMPLETE;
    dev->pair_time = get_time_ms(handle);
    dev->online = SPROTOCOL_DEVICE_ONLINE;
    
    /* 清除配对状态 */
    handle->pairing_state.active = 0;
    handle->pairing_state.slave_addr = 0;
    handle->pairing_state.start_time = 0;
    
    /* 发送配对确认 */
    send_pair_frame(handle, frame->src_addr, SPROTOCOL_MSG_PAIR_CFM, NULL, 0);
    
    /* 通知应用层 */
    if (handle->config.pair_cb) {
        handle->config.pair_cb(frame->src_addr, SPROTOCOL_PAIR_COMPLETE, handle->config.user_data);
    }
}

void pairing_handle_confirm(sprotocol_handle_t handle, const sprotocol_frame_t* frame) {
    if (!handle || !frame) {
        return;
    }
    
    /* 只有从机处理配对确认 */
    if (handle->config.role != SPROTOCOL_ROLE_SLAVE) {
        return;
    }
    
    /* 验证源地址 */
    if (frame->src_addr != SPROTOCOL_ADDR_MASTER) {
        return;
    }
    
    /* 获取设备 */
    sprotocol_device_t* dev = device_get(handle, frame->src_addr);
    if (!dev) {
        return;
    }
    
    /* 更新设备状态 */
    dev->pair_status = SPROTOCOL_PAIR_COMPLETE;
    dev->online = SPROTOCOL_DEVICE_ONLINE;
    
    /* 通知应用层 */
    if (handle->config.pair_cb) {
        handle->config.pair_cb(frame->src_addr, SPROTOCOL_PAIR_COMPLETE, handle->config.user_data);
    }
}

void pairing_check_timeout(sprotocol_handle_t handle) {
    if (!handle || !handle->pairing_state.active) {
        return;
    }
    
    uint32_t current_time = get_time_ms(handle);
    uint32_t elapsed = current_time - handle->pairing_state.start_time;
    
    if (elapsed >= handle->config.pair_timeout) {
        /* 配对超时 */
        uint8_t slave_addr = handle->pairing_state.slave_addr;
        
        sprotocol_device_t* dev = device_get(handle, slave_addr);
        if (dev && dev->pair_status == SPROTOCOL_PAIR_PENDING) {
            dev->pair_status = SPROTOCOL_PAIR_NONE;
        }
        
        /* 清除配对状态 */
        handle->pairing_state.active = 0;
        handle->pairing_state.slave_addr = 0;
        handle->pairing_state.start_time = 0;
        
        /* 通知应用层 */
        if (handle->config.pair_cb) {
            handle->config.pair_cb(slave_addr, SPROTOCOL_PAIR_NONE, handle->config.user_data);
        }
    }
}
