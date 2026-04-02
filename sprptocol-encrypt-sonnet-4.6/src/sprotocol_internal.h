#ifndef SPROTOCOL_INTERNAL_H
#define SPROTOCOL_INTERNAL_H

#include "sprotocol.h"
#include <string.h>

/* -----------------------------------------------------------------------
 * 帧序列化/反序列化辅助宏
 * 线格式（字节序列，little-endian uint16）：
 *   [0]    header
 *   [1]    version
 *   [2]    flags (1 字节)
 *   [3]    src_addr
 *   [4]    dest_addr
 *   [5-6]  seq      LE
 *   [7-8]  domain_id LE
 *   [9]    msg_type
 *   [10]   payload_len
 *   [11..11+payload_len-1] payload
 *   [last-1..last] crc16 LE
 * ----------------------------------------------------------------------- */
#define FRAME_HDR_SIZE   11    /* header...payload_len 共 11 字节 */
#define FRAME_CRC_SIZE   2
/* 最小帧长 = 头 + 0载荷 + CRC */
#define FRAME_MIN_SIZE   (FRAME_HDR_SIZE + FRAME_CRC_SIZE)
/* 最大帧长 */
#define FRAME_MAX_SIZE   (FRAME_HDR_SIZE + SPROTOCOL_MAX_PAYLOAD_LEN + FRAME_CRC_SIZE)

/* flags 字节位定义 */
#define FLAG_BROADCAST   (1u << 0)
#define FLAG_NEED_ACK    (1u << 1)
#define FLAG_ENCRYPTED   (1u << 2)
#define FLAG_RETRANSMIT  (1u << 3)
#define FLAG_FRAGMENTED  (1u << 4)

static inline uint8_t flags_to_byte(sprotocol_flags_t f) {
    uint8_t b = 0;
    if (f.broadcast)  b |= FLAG_BROADCAST;
    if (f.need_ack)   b |= FLAG_NEED_ACK;
    if (f.encrypted)  b |= FLAG_ENCRYPTED;
    if (f.retransmit) b |= FLAG_RETRANSMIT;
    if (f.fragmented) b |= FLAG_FRAGMENTED;
    return b;
}

static inline sprotocol_flags_t byte_to_flags(uint8_t b) {
    sprotocol_flags_t f;
    memset(&f, 0, sizeof(f));
    f.broadcast  = (b & FLAG_BROADCAST)  ? 1 : 0;
    f.need_ack   = (b & FLAG_NEED_ACK)   ? 1 : 0;
    f.encrypted  = (b & FLAG_ENCRYPTED)  ? 1 : 0;
    f.retransmit = (b & FLAG_RETRANSMIT) ? 1 : 0;
    f.fragmented = (b & FLAG_FRAGMENTED) ? 1 : 0;
    return f;
}

/* ----------------------------------------------------------------------- */
/* 加密上下文（每个 peer 独立）                                             */
/* ----------------------------------------------------------------------- */
#define CRYPTO_KEY_SIZE    16   /* AES-128 密钥 16 字节 */
#define CRYPTO_PUBKEY_SIZE 65   /* secp256r1 未压缩公钥 65 字节 */

typedef struct {
    uint8_t shared_key[CRYPTO_KEY_SIZE];  /* 派生的 AES 密钥 */
    uint8_t ready;                         /* 1 = 密钥已就绪 */
} sprotocol_peer_crypto_t;

/* ----------------------------------------------------------------------- */
/* 内部句柄                                                                 */
/* ----------------------------------------------------------------------- */
struct sprotocol_handle {
    sprotocol_config_t config;

    /* 设备表（主机最多 5 个从机，从机只有一个主机条目 slaves[0]） */
    sprotocol_device_t slaves[SPROTOCOL_MAX_SLAVES];
    int slave_count;

    /* 本机发送序列号 */
    uint16_t local_seq;

    /* 黑名单 */
    sprotocol_blacklist_entry_t blacklist[SPROTOCOL_MAX_BLACKLIST];
    int blacklist_count;

    /* ECC 上下文（opaque，由 sprotocol_crypto.c 管理） */
    void *ecc_ctx;

    /* 本机 ECC 公钥（用于配对时传输） */
    uint8_t local_pubkey[CRYPTO_PUBKEY_SIZE];
    size_t  local_pubkey_len;

    /* 每个 peer 的对称密钥 */
    sprotocol_peer_crypto_t peer_crypto[SPROTOCOL_MAX_SLAVES];

    /* 配对超时追踪（ms，0 = 无待配对） */
    uint32_t pair_start_time[SPROTOCOL_MAX_SLAVES];

    /* 上次序列号保存时间 */
    uint32_t last_seq_save_time;
};

/* ----------------------------------------------------------------------- */
/* 查找从机槽位辅助函数                                                      */
/* ----------------------------------------------------------------------- */
static inline int find_slave_idx(struct sprotocol_handle *h, uint8_t addr) {
    for (int i = 0; i < h->slave_count; i++) {
        if (h->slaves[i].addr == addr) return i;
    }
    return -1;
}

/* 查找或创建（仅在已知地址合法时使用） */
static inline int find_or_create_slave(struct sprotocol_handle *h, uint8_t addr) {
    int idx = find_slave_idx(h, addr);
    if (idx >= 0) return idx;
    if (h->slave_count >= SPROTOCOL_MAX_SLAVES) return -1;
    idx = h->slave_count++;
    memset(&h->slaves[idx], 0, sizeof(sprotocol_device_t));
    h->slaves[idx].addr = addr;
    return idx;
}

#endif /* SPROTOCOL_INTERNAL_H */
