/**
 * @file comm.c
 * @brief 数据通信模块
 */

#include "sprotocol.h"
#include "sprotocol_internal.h"
#include <string.h>

int sprotocol_send(sprotocol_handle_t handle, uint8_t dest_addr, uint16_t domain_id,
                   uint8_t msg_type, const uint8_t* payload, size_t len) {
    if (!handle) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }
    
    if (len > SPROTOCOL_MAX_PAYLOAD_LEN) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }
    
    /* 检查目的地址 */
    if (dest_addr != SPROTOCOL_ADDR_BROADCAST) {
        if (handle->config.role == SPROTOCOL_ROLE_MASTER) {
            /* 主机只能发给从机 */
            if (dest_addr < SPROTOCOL_MIN_SLAVE_ADDR || dest_addr > SPROTOCOL_MAX_SLAVE_ADDR) {
                return SPROTOCOL_ERR_INVALID_ARG;
            }
        } else {
            /* 从机只能发给主机 */
            if (dest_addr != SPROTOCOL_ADDR_MASTER) {
                return SPROTOCOL_ERR_INVALID_ARG;
            }
        }
    }
    
    /* 构建帧 */
    sprotocol_frame_t frame;
    memset(&frame, 0, sizeof(frame));
    
    frame.header = SPROTOCOL_FRAME_HEADER;
    frame.version = SPROTOCOL_FRAME_VERSION;
    frame.flags.need_ack = 1;  /* 数据消息需要ACK */
    frame.src_addr = handle->config.local_addr;
    frame.dest_addr = dest_addr;
    frame.seq = seq_get_tx(handle, dest_addr);
    frame.domain_id = domain_id;
    frame.msg_type = msg_type;
    frame.payload_len = (uint8_t)len;
    
    if (len > 0 && payload) {
        memcpy(frame.payload, payload, len);
    }
    
    /* 序列化并发送 */
    uint8_t buffer[512];
    size_t buffer_len;
    int ret = sprotocol_frame_pack(&frame, buffer, &buffer_len);
    if (ret != SPROTOCOL_OK) {
        return ret;
    }
    
    handle->config.send_cb(buffer, buffer_len, handle->config.user_data);
    
    return SPROTOCOL_OK;
}

int sprotocol_broadcast(sprotocol_handle_t handle, uint16_t domain_id,
                        uint8_t msg_type, const uint8_t* payload, size_t len) {
    if (!handle) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }
    
    /* 只有主机可以广播 */
    if (handle->config.role != SPROTOCOL_ROLE_MASTER) {
        return SPROTOCOL_ERR_INVALID_STATE;
    }
    
    if (len > SPROTOCOL_MAX_PAYLOAD_LEN) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }
    
    /* 构建广播帧 */
    sprotocol_frame_t frame;
    memset(&frame, 0, sizeof(frame));
    
    frame.header = SPROTOCOL_FRAME_HEADER;
    frame.version = SPROTOCOL_FRAME_VERSION;
    frame.flags.broadcast = 1;
    frame.flags.need_ack = 0;  /* 广播不需要ACK */
    frame.src_addr = handle->config.local_addr;
    frame.dest_addr = SPROTOCOL_ADDR_BROADCAST;
    frame.seq = seq_get_tx(handle, SPROTOCOL_ADDR_BROADCAST);
    frame.domain_id = domain_id;
    frame.msg_type = msg_type;
    frame.payload_len = (uint8_t)len;
    
    if (len > 0 && payload) {
        memcpy(frame.payload, payload, len);
    }
    
    /* 序列化并发送 */
    uint8_t buffer[512];
    size_t buffer_len;
    int ret = sprotocol_frame_pack(&frame, buffer, &buffer_len);
    if (ret != SPROTOCOL_OK) {
        return ret;
    }
    
    handle->config.send_cb(buffer, buffer_len, handle->config.user_data);
    
    return SPROTOCOL_OK;
}
