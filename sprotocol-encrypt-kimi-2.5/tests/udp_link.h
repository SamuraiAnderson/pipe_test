/**
 * @file udp_link.h
 * @brief UDP通信链路模拟
 */

#ifndef UDP_LINK_H
#define UDP_LINK_H

#include <stdint.h>
#include <stddef.h>

typedef struct udp_link udp_link_t;

/* 创建UDP链路 */
udp_link_t* udp_link_create(const char* ip, uint16_t port);

/* 销毁UDP链路 */
void udp_link_destroy(udp_link_t* link);

/* 发送数据 */
int udp_link_send(udp_link_t* link, const uint8_t* data, size_t len, const char* dest_ip, uint16_t dest_port);

/* 接收数据 */
int udp_link_recv(udp_link_t* link, uint8_t* buffer, size_t buffer_size, 
                  char* from_ip, size_t ip_size, uint16_t* from_port, int timeout_ms);

/* 获取发送/接收统计 */
int udp_link_get_send_count(udp_link_t* link);
int udp_link_get_recv_count(udp_link_t* link);

/* 清除接收缓冲区 */
void udp_link_clear_recv_buffer(udp_link_t* link);

#endif /* UDP_LINK_H */
