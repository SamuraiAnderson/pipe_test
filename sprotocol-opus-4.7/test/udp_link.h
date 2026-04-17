/**
 * @file udp_link.h
 * @brief UDP 测试链路：绑定本地端口 + 启动接收线程，并把 sprotocol 的
 *        send_cb 桥接到 sendto()，使用 127.0.0.1 上的 UDP 端口模拟无线信道。
 *
 * 地址映射规则（Master 约定一致）：
 *   - Master (addr=0x00)        → 9000
 *   - Slave  (addr=0x10 + i)    → 9001 + i
 *   - 广播 (dest=0xFF)          → 发到 Master + 所有 Slave 端口
 */

#ifndef UDP_LINK_H
#define UDP_LINK_H

#include "sprotocol.h"

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define UDP_LINK_BASE_PORT_MASTER  9000
#define UDP_LINK_BASE_PORT_SLAVE   9001
#define UDP_LINK_MAX_SLAVES        SPROTOCOL_MAX_SLAVES

typedef struct udp_link udp_link_t;

/**
 * 创建链路。role_addr=本地地址；handle 可在 init 之后通过 udp_link_attach 绑定。
 * @return 新链路（失败返回 NULL）
 */
udp_link_t* udp_link_create(uint8_t local_addr);

/** 绑定 handle：链路上所有入站帧调用 sprotocol_input(handle, ...) */
void udp_link_attach(udp_link_t* link, sprotocol_handle_t h);

/** send_cb 回调入口（供 sprotocol_config_t::send_cb 注册） */
void udp_link_send_cb(const uint8_t* data, size_t len, void* user_data);

/** 人为丢弃入站帧（用于心跳离线测试）。drop=1 表示丢弃所有，0 恢复。 */
void udp_link_set_drop(udp_link_t* link, int drop);

/** 发送端也被抑制（若不希望出站也受影响，不需调用） */
void udp_link_set_tx_drop(udp_link_t* link, int drop);

/** 关闭并释放资源（阻塞等待 rx 线程退出） */
void udp_link_destroy(udp_link_t* link);

#ifdef __cplusplus
}
#endif

#endif /* UDP_LINK_H */
