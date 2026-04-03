/**
 * @file core.c
 * @brief 核心模块：初始化、主循环、输入处理
 */

#include "sprotocol.h"
#include "sprotocol_internal.h"
#include <stdlib.h>
#include <string.h>

const char* sprotocol_get_version(void) {
    static char version[32];
    snprintf(version, sizeof(version), "%d.%d.%d",
             SPROTOCOL_VERSION_MAJOR,
             SPROTOCOL_VERSION_MINOR,
             SPROTOCOL_VERSION_PATCH);
    return version;
}

sprotocol_handle_t sprotocol_init(const sprotocol_config_t* config) {
    if (!config) {
        return NULL;
    }
    
    /* 验证角色和地址 */
    if (config->role == SPROTOCOL_ROLE_MASTER) {
        if (config->local_addr != SPROTOCOL_ADDR_MASTER) {
            return NULL;
        }
    } else {
        if (config->local_addr < SPROTOCOL_MIN_SLAVE_ADDR ||
            config->local_addr > SPROTOCOL_MAX_SLAVE_ADDR) {
            return NULL;
        }
    }
    
    /* 验证最大从机数量 */
    if (config->max_slaves == 0 || config->max_slaves > SPROTOCOL_MAX_SLAVES) {
        return NULL;
    }
    
    /* 验证必要回调 */
    if (!config->send_cb || !config->get_time) {
        return NULL;
    }
    
    /* 分配句柄 */
    sprotocol_handle_t handle = calloc(1, sizeof(struct sprotocol_handle));
    if (!handle) {
        return NULL;
    }
    
    /* 复制配置 */
    memcpy(&handle->config, config, sizeof(sprotocol_config_t));
    
    /* 设置默认值 */
    if (handle->config.heartbeat_timeout == 0) {
        handle->config.heartbeat_timeout = 3000;  /* 默认3秒 */
    }
    if (handle->config.pair_timeout == 0) {
        handle->config.pair_timeout = 5000;  /* 默认5秒 */
    }
    if (handle->config.seq_save_interval == 0) {
        handle->config.seq_save_interval = 60000;  /* 默认1分钟 */
    }
    if (handle->config.seq_check_interval == 0) {
        handle->config.seq_check_interval = 1000;  /* 默认1秒 */
    }
    
    /* 初始化设备表 */
    for (int i = 0; i < SPROTOCOL_MAX_SLAVES; i++) {
        handle->devices[i].addr = 0;
        handle->devices[i].pair_status = SPROTOCOL_PAIR_NONE;
        handle->devices[i].online = SPROTOCOL_DEVICE_OFFLINE;
        handle->devices[i].seq_tx = 0;
        handle->devices[i].seq_rx = 0;
        handle->devices[i].last_heartbeat = 0;
        handle->devices[i].pair_time = 0;
    }
    
    /* 初始化黑名单 */
    blacklist_init(handle);
    
    /* 初始化序列号 */
    seq_init(handle);
    
    return handle;
}

void sprotocol_deinit(sprotocol_handle_t handle) {
    if (!handle) {
        return;
    }
    
    /* 清理加密资源 */
    crypto_deinit(handle);
    
    free(handle);
}

void sprotocol_poll(sprotocol_handle_t handle) {
    if (!handle) {
        return;
    }
    
    /* 检查配对超时 */
    if (handle->pairing_state.active) {
        pairing_check_timeout(handle);
    }
    
    /* 检查心跳超时 */
    heartbeat_check_timeout(handle);
    
    /* 定期保存序列号 */
    seq_save_periodic(handle);
    
    /* 更新黑名单 */
    blacklist_update(handle);
}

void sprotocol_input(sprotocol_handle_t handle, const uint8_t* data, size_t len) {
    if (!handle || !data || len == 0) {
        return;
    }
    
    /* 解析帧 */
    sprotocol_frame_t frame;
    memset(&frame, 0, sizeof(frame));
    
    int ret = sprotocol_frame_unpack(data, len, &frame);
    if (ret != SPROTOCOL_OK) {
        return;  /* CRC错误或格式错误 */
    }
    
    /* 验证目的地址 */
    if (frame.dest_addr != handle->config.local_addr &&
        frame.dest_addr != SPROTOCOL_ADDR_BROADCAST) {
        return;  /* 不是发给我们的 */
    }
    
    /* 检查黑名单 */
    if (blacklist_check(handle, frame.src_addr)) {
        return;
    }
    
    /* 更新接收序列号 */
    seq_update_rx(handle, frame.src_addr, frame.seq);
    
    /* 根据消息类型分发处理 */
    switch (frame.msg_type) {
        case SPROTOCOL_MSG_PAIR_REQ:
            pairing_handle_request(handle, &frame);
            break;
            
        case SPROTOCOL_MSG_PAIR_RSP:
            pairing_handle_response(handle, &frame);
            break;
            
        case SPROTOCOL_MSG_PAIR_CFM:
            pairing_handle_confirm(handle, &frame);
            break;
            
        case SPROTOCOL_MSG_HEARTBEAT:
            heartbeat_handle(handle, &frame);
            break;
            
        case SPROTOCOL_MSG_DATA:
            if (handle->config.recv_cb) {
                handle->config.recv_cb(frame.src_addr, frame.domain_id,
                                      frame.msg_type, frame.payload,
                                      frame.payload_len, handle->config.user_data);
            }
            break;
            
        case SPROTOCOL_MSG_ACK:
        case SPROTOCOL_MSG_NACK:
            /* TODO: 处理ACK/NACK */
            break;
            
        default:
            /* 未知消息类型 */
            break;
    }
}
