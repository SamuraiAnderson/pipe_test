#include "udp_link.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

struct udp_link {
    uint8_t local_addr;
    int sock;
    pthread_t rx_thread;
    atomic_int running;
    atomic_int drop_rx;
    atomic_int drop_tx;
    sprotocol_handle_t handle;
};

static uint16_t port_for_addr(uint8_t addr)
{
    if (addr == SPROTOCOL_ADDR_MASTER) return UDP_LINK_BASE_PORT_MASTER;
    if (addr >= SPROTOCOL_MIN_SLAVE_ADDR && addr <= SPROTOCOL_MAX_SLAVE_ADDR) {
        return (uint16_t)(UDP_LINK_BASE_PORT_SLAVE + (addr - SPROTOCOL_MIN_SLAVE_ADDR));
    }
    return 0;
}

static void* rx_loop(void* arg)
{
    udp_link_t* link = (udp_link_t*)arg;
    uint8_t buf[2048];
    while (atomic_load(&link->running)) {
        struct sockaddr_in from; socklen_t fl = sizeof(from);
        ssize_t n = recvfrom(link->sock, buf, sizeof(buf), 0,
                             (struct sockaddr*)&from, &fl);
        if (n <= 0) {
            if (!atomic_load(&link->running)) break;
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) continue;
            break;
        }
        if (atomic_load(&link->drop_rx)) continue;
        if (link->handle) sprotocol_input(link->handle, buf, (size_t)n);
    }
    return NULL;
}

udp_link_t* udp_link_create(uint8_t local_addr)
{
    uint16_t port = port_for_addr(local_addr);
    if (!port) return NULL;

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return NULL;

    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
#ifdef SO_REUSEPORT
    setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
#endif

    struct timeval tv = { .tv_sec = 0, .tv_usec = 200000 }; /* 200ms 超时便于关闭 */
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(s, (struct sockaddr*)&a, sizeof(a)) < 0) {
        fprintf(stderr, "udp_link_create: bind %u failed: %s\n", port, strerror(errno));
        close(s);
        return NULL;
    }

    udp_link_t* link = (udp_link_t*)calloc(1, sizeof(*link));
    if (!link) { close(s); return NULL; }
    link->local_addr = local_addr;
    link->sock = s;
    atomic_store(&link->running, 1);
    atomic_store(&link->drop_rx, 0);
    atomic_store(&link->drop_tx, 0);

    if (pthread_create(&link->rx_thread, NULL, rx_loop, link) != 0) {
        close(s);
        free(link);
        return NULL;
    }
    return link;
}

void udp_link_attach(udp_link_t* link, sprotocol_handle_t h)
{
    if (!link) return;
    link->handle = h;
}

void udp_link_set_drop(udp_link_t* link, int drop)
{
    if (!link) return;
    atomic_store(&link->drop_rx, drop ? 1 : 0);
}

void udp_link_set_tx_drop(udp_link_t* link, int drop)
{
    if (!link) return;
    atomic_store(&link->drop_tx, drop ? 1 : 0);
}

static void send_to_port(int sock, uint16_t port, const uint8_t* data, size_t len)
{
    struct sockaddr_in to;
    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_port = htons(port);
    to.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    (void)sendto(sock, data, len, 0, (struct sockaddr*)&to, sizeof(to));
}

void udp_link_send_cb(const uint8_t* data, size_t len, void* user_data)
{
    udp_link_t* link = (udp_link_t*)user_data;
    if (!link || !data || len < 11) return;
    if (atomic_load(&link->drop_tx)) return;

    uint8_t dest = data[4];
    if (dest == SPROTOCOL_ADDR_BROADCAST) {
        send_to_port(link->sock, UDP_LINK_BASE_PORT_MASTER, data, len);
        for (int i = 0; i < UDP_LINK_MAX_SLAVES; ++i) {
            send_to_port(link->sock,
                         (uint16_t)(UDP_LINK_BASE_PORT_SLAVE + i), data, len);
        }
    } else {
        uint16_t port = port_for_addr(dest);
        if (port) send_to_port(link->sock, port, data, len);
    }
}

void udp_link_destroy(udp_link_t* link)
{
    if (!link) return;
    atomic_store(&link->running, 0);
    shutdown(link->sock, SHUT_RDWR);
    pthread_join(link->rx_thread, NULL);
    close(link->sock);
    free(link);
}
