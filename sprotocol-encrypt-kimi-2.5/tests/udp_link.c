/**
 * @file udp_link.c
 * @brief UDP通信链路模拟实现
 */

#include "udp_link.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>

struct udp_link {
    int sockfd;
    struct sockaddr_in local_addr;
    int send_count;
    int recv_count;
};

udp_link_t* udp_link_create(const char* ip, uint16_t port) {
    udp_link_t* link = calloc(1, sizeof(udp_link_t));
    if (!link) {
        return NULL;
    }
    
    link->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (link->sockfd < 0) {
        free(link);
        return NULL;
    }
    
    /* 设置非阻塞模式 */
    int flags = fcntl(link->sockfd, F_GETFL, 0);
    fcntl(link->sockfd, F_SETFL, flags | O_NONBLOCK);
    
    /* 允许地址复用 */
    int reuse = 1;
    setsockopt(link->sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    
    /* 绑定本地地址 */
    memset(&link->local_addr, 0, sizeof(link->local_addr));
    link->local_addr.sin_family = AF_INET;
    link->local_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &link->local_addr.sin_addr);
    
    if (bind(link->sockfd, (struct sockaddr*)&link->local_addr, sizeof(link->local_addr)) < 0) {
        close(link->sockfd);
        free(link);
        return NULL;
    }
    
    link->send_count = 0;
    link->recv_count = 0;
    
    return link;
}

void udp_link_destroy(udp_link_t* link) {
    if (!link) {
        return;
    }
    
    if (link->sockfd >= 0) {
        close(link->sockfd);
    }
    
    free(link);
}

int udp_link_send(udp_link_t* link, const uint8_t* data, size_t len, 
                  const char* dest_ip, uint16_t dest_port) {
    if (!link || !data || link->sockfd < 0) {
        return -1;
    }
    
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(dest_port);
    inet_pton(AF_INET, dest_ip, &dest_addr.sin_addr);
    
    ssize_t sent = sendto(link->sockfd, data, len, 0,
                          (struct sockaddr*)&dest_addr, sizeof(dest_addr));
    
    if (sent > 0) {
        link->send_count++;
    }
    
    return (int)sent;
}

int udp_link_recv(udp_link_t* link, uint8_t* buffer, size_t buffer_size,
                  char* from_ip, size_t ip_size, uint16_t* from_port, int timeout_ms) {
    if (!link || !buffer || link->sockfd < 0) {
        return -1;
    }
    
    /* 使用select实现超时 */
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(link->sockfd, &readfds);
    
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    
    int ret = select(link->sockfd + 1, &readfds, NULL, NULL, 
                     timeout_ms >= 0 ? &tv : NULL);
    
    if (ret <= 0) {
        return ret;  /* 超时或无数据 */
    }
    
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);
    
    ssize_t received = recvfrom(link->sockfd, buffer, buffer_size, 0,
                                (struct sockaddr*)&from_addr, &from_len);
    
    if (received > 0) {
        link->recv_count++;
        
        if (from_ip && ip_size > 0) {
            inet_ntop(AF_INET, &from_addr.sin_addr, from_ip, ip_size);
        }
        
        if (from_port) {
            *from_port = ntohs(from_addr.sin_port);
        }
    }
    
    return (int)received;
}

int udp_link_get_send_count(udp_link_t* link) {
    return link ? link->send_count : 0;
}

int udp_link_get_recv_count(udp_link_t* link) {
    return link ? link->recv_count : 0;
}

void udp_link_clear_recv_buffer(udp_link_t* link) {
    if (!link || link->sockfd < 0) {
        return;
    }
    
    uint8_t buffer[1024];
    while (recvfrom(link->sockfd, buffer, sizeof(buffer), 0, NULL, NULL) > 0) {
        /* 清空所有待接收数据 */
    }
}
