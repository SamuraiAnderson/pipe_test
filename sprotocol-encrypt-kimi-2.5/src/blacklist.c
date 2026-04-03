/**
 * @file blacklist.c
 * @brief 黑名单管理模块
 */

#include "sprotocol.h"
#include "sprotocol_internal.h"
#include <string.h>

void blacklist_init(sprotocol_handle_t handle) {
    if (!handle) {
        return;
    }
    
    memset(handle->blacklist, 0, sizeof(handle->blacklist));
}

int blacklist_check(sprotocol_handle_t handle, uint8_t addr) {
    if (!handle || addr == 0) {
        return 0;
    }
    
    uint32_t current_time = get_time_ms(handle);
    
    for (int i = 0; i < SPROTOCOL_MAX_BLACKLIST; i++) {
        if (handle->blacklist[i].addr == addr) {
            /* 检查是否过期 */
            if (handle->blacklist[i].expire_time > 0 &&
                current_time > handle->blacklist[i].expire_time) {
                /* 过期，移除 */
                memset(&handle->blacklist[i], 0, sizeof(sprotocol_blacklist_entry_t));
                return 0;
            }
            return 1;  /* 在黑名单中 */
        }
    }
    
    return 0;
}

void blacklist_add(sprotocol_handle_t handle, uint8_t addr) {
    if (!handle || addr == 0) {
        return;
    }
    
    /* 检查是否已在黑名单中 */
    if (blacklist_check(handle, addr)) {
        return;
    }
    
    uint32_t current_time = get_time_ms(handle);
    
    /* 查找空闲位置 */
    int free_idx = -1;
    for (int i = 0; i < SPROTOCOL_MAX_BLACKLIST; i++) {
        if (handle->blacklist[i].addr == 0) {
            free_idx = i;
            break;
        }
    }
    
    if (free_idx < 0) {
        /* 黑名单已满，替换最旧的 */
        uint32_t oldest_time = current_time;
        for (int i = 0; i < SPROTOCOL_MAX_BLACKLIST; i++) {
            if (handle->blacklist[i].add_time < oldest_time) {
                oldest_time = handle->blacklist[i].add_time;
                free_idx = i;
            }
        }
    }
    
    if (free_idx >= 0) {
        handle->blacklist[free_idx].addr = addr;
        handle->blacklist[free_idx].add_time = current_time;
        handle->blacklist[free_idx].expire_time = current_time + SPROTOCOL_BLACKLIST_EXPIRE;
        handle->blacklist[free_idx].trigger_count = SPROTOCOL_BLACKLIST_LIMIT;
    }
}

void blacklist_remove(sprotocol_handle_t handle, uint8_t addr) {
    if (!handle || addr == 0) {
        return;
    }
    
    for (int i = 0; i < SPROTOCOL_MAX_BLACKLIST; i++) {
        if (handle->blacklist[i].addr == addr) {
            memset(&handle->blacklist[i], 0, sizeof(sprotocol_blacklist_entry_t));
            return;
        }
    }
}

void blacklist_update(sprotocol_handle_t handle) {
    if (!handle) {
        return;
    }
    
    uint32_t current_time = get_time_ms(handle);
    
    for (int i = 0; i < SPROTOCOL_MAX_BLACKLIST; i++) {
        if (handle->blacklist[i].addr != 0) {
            /* 检查是否过期 */
            if (handle->blacklist[i].expire_time > 0 &&
                current_time > handle->blacklist[i].expire_time) {
                memset(&handle->blacklist[i], 0, sizeof(sprotocol_blacklist_entry_t));
            }
            /* TODO: 窗口期内的触发次数处理 */
        }
    }
}

int blacklist_get_count(sprotocol_handle_t handle) {
    if (!handle) {
        return 0;
    }
    
    int count = 0;
    for (int i = 0; i < SPROTOCOL_MAX_BLACKLIST; i++) {
        if (handle->blacklist[i].addr != 0) {
            count++;
        }
    }
    
    return count;
}

void blacklist_trigger(sprotocol_handle_t handle, uint8_t addr) {
    if (!handle || addr == 0) {
        return;
    }
    
    uint32_t current_time = get_time_ms(handle);
    
    /* 查找或创建设备条目 */
    int idx = -1;
    for (int i = 0; i < SPROTOCOL_MAX_BLACKLIST; i++) {
        if (handle->blacklist[i].addr == addr) {
            idx = i;
            break;
        }
    }
    
    if (idx < 0) {
        /* 查找空闲位置 */
        for (int i = 0; i < SPROTOCOL_MAX_BLACKLIST; i++) {
            if (handle->blacklist[i].addr == 0) {
                idx = i;
                handle->blacklist[i].addr = addr;
                handle->blacklist[i].add_time = current_time;
                break;
            }
        }
    }
    
    if (idx >= 0) {
        handle->blacklist[idx].trigger_count++;
        
        /* 检查是否超过限制 */
        if (handle->blacklist[idx].trigger_count >= SPROTOCOL_BLACKLIST_LIMIT) {
            handle->blacklist[idx].expire_time = current_time + SPROTOCOL_BLACKLIST_EXPIRE;
        }
    }
}

/* 公开API */
int sprotocol_is_blacklisted(sprotocol_handle_t handle, uint8_t addr) {
    return blacklist_check(handle, addr);
}

int sprotocol_get_blacklist_count(sprotocol_handle_t handle) {
    return blacklist_get_count(handle);
}
