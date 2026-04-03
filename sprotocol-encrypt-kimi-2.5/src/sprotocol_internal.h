/**
 * @file sprotocol_internal.h
 * @brief 内部数据结构和函数声明
 */

#ifndef SPROTOCOL_INTERNAL_H
#define SPROTOCOL_INTERNAL_H

#include "sprotocol.h"
#include <string.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 内部配对状态结构 */
typedef struct {
    uint8_t active;
    uint8_t slave_addr;
    uint32_t start_time;
} pairing_state_t;

/* 内部序列号状态结构 */
typedef struct {
    uint32_t last_save_time;
} seq_state_t;

/* 内部句柄结构定义 */
struct sprotocol_handle {
    sprotocol_config_t config;
    sprotocol_device_t devices[SPROTOCOL_MAX_SLAVES];
    sprotocol_blacklist_entry_t blacklist[SPROTOCOL_MAX_BLACKLIST];
    pairing_state_t pairing_state;
    seq_state_t seq_state;
};

/* 帧序列化/反序列化 */
int sprotocol_frame_pack(const sprotocol_frame_t* frame, uint8_t* buffer, size_t* len);
int sprotocol_frame_unpack(const uint8_t* buffer, size_t len, sprotocol_frame_t* frame);

/* 设备表管理 */
sprotocol_device_t* device_get(sprotocol_handle_t handle, uint8_t addr);
sprotocol_device_t* device_add(sprotocol_handle_t handle, uint8_t addr);
void device_remove(sprotocol_handle_t handle, uint8_t addr);
void device_clear_all(sprotocol_handle_t handle);
int device_get_list(sprotocol_handle_t handle, uint8_t* addrs, uint8_t max_count);

/* 配对管理 */
int pairing_request(sprotocol_handle_t handle, uint8_t slave_addr);
void pairing_handle_request(sprotocol_handle_t handle, const sprotocol_frame_t* frame);
void pairing_handle_response(sprotocol_handle_t handle, const sprotocol_frame_t* frame);
void pairing_handle_confirm(sprotocol_handle_t handle, const sprotocol_frame_t* frame);
void pairing_check_timeout(sprotocol_handle_t handle);

/* 心跳管理 */
void heartbeat_send(sprotocol_handle_t handle);
void heartbeat_handle(sprotocol_handle_t handle, const sprotocol_frame_t* frame);
void heartbeat_check_timeout(sprotocol_handle_t handle);

/* 黑名单管理 */
void blacklist_init(sprotocol_handle_t handle);
int blacklist_check(sprotocol_handle_t handle, uint8_t addr);
void blacklist_add(sprotocol_handle_t handle, uint8_t addr);
void blacklist_remove(sprotocol_handle_t handle, uint8_t addr);
void blacklist_update(sprotocol_handle_t handle);
int blacklist_get_count(sprotocol_handle_t handle);
void blacklist_trigger(sprotocol_handle_t handle, uint8_t addr);

/* 加密模块 */
int crypto_init(sprotocol_handle_t handle);
void crypto_deinit(sprotocol_handle_t handle);
int crypto_ecc_generate_keypair(sprotocol_handle_t handle, uint8_t* pubkey, size_t* pubkey_len);
int crypto_ecc_compute_shared_secret(sprotocol_handle_t handle, const uint8_t* peer_pubkey, 
                                      size_t peer_pubkey_len, uint8_t* shared_secret, size_t* secret_len);
int crypto_encrypt(sprotocol_handle_t handle, const uint8_t* plaintext, size_t plaintext_len,
                   uint8_t* ciphertext, size_t* ciphertext_len);
int crypto_decrypt(sprotocol_handle_t handle, const uint8_t* ciphertext, size_t ciphertext_len,
                   uint8_t* plaintext, size_t* plaintext_len);

/* 序列号管理 */
void seq_init(sprotocol_handle_t handle);
uint16_t seq_get_tx(sprotocol_handle_t handle, uint8_t addr);
void seq_update_rx(sprotocol_handle_t handle, uint8_t addr, uint16_t seq);
void seq_save_periodic(sprotocol_handle_t handle);

/* 时间获取辅助函数 */
static inline uint32_t get_time_ms(sprotocol_handle_t handle) {
    if (handle && handle->config.get_time) {
        return handle->config.get_time();
    }
    return 0;
}

#ifdef __cplusplus
}
#endif

#endif /* SPROTOCOL_INTERNAL_H */
