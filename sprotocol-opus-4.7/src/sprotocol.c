/**
 * @file sprotocol.c
 * @brief 主从无线通信协议实现
 *
 * 主要模块：
 *   - 帧编解码 + CRC16-CCITT
 *   - 主从设备表 / 配对状态机
 *   - 序列号与重放保护
 *   - 心跳与在线状态
 *   - 黑名单
 *   - 基于 ECDH+AES-128-CTR+HMAC-SHA256 的安全通道
 */

#include "sprotocol.h"
#include "sprotocol_crypto.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================ */
/* 常量与本地宏                                                 */
/* ============================================================ */

/* 帧线缆格式（变长，避免结构体 padding）：
 *
 *  off  size  field
 *   0    1    header (0xAA)
 *   1    1    version
 *   2    1    flags  (bit0=broadcast,bit1=need_ack,bit2=encrypted,
 *                     bit3=retransmit,bit4=fragmented)
 *   3    1    src_addr
 *   4    1    dest_addr
 *   5    2    seq        (LE)
 *   7    2    domain_id  (LE)
 *   9    1    msg_type
 *  10    1    payload_len (N)
 *  11    N    payload
 *  11+N  2    crc16(LE)  -- 覆盖前 11+N 字节
 */
#define WIRE_HEADER_LEN     11
#define WIRE_CRC_LEN        2
#define WIRE_OVERHEAD       (WIRE_HEADER_LEN + WIRE_CRC_LEN)
#define WIRE_MAX_LEN        (WIRE_OVERHEAD + SPROTOCOL_MAX_PAYLOAD_LEN)

/* 加密载荷布局: nonce(12) || ciphertext(L) || mac(8) */
#define ENC_OVERHEAD        (SPC_FRAME_NONCE_LEN + SPC_HMAC_TAG_LEN)

#define HANDSHAKE_INFO      "sprotocol-keys"

/* ============================================================ */
/* 内部结构体                                                   */
/* ============================================================ */

typedef struct {
    spc_session_t sess;
} peer_crypto_t;

struct sprotocol_handle {
    sprotocol_config_t cfg;

    pthread_mutex_t lock;

    /* 设备表 ----------------------------------------------------
     * Master: devices[i] 表示 slave addr = 0x10 + i  (i ∈ [0, max_slaves))
     * Slave : devices[0] 表示 master (addr = 0x00)
     */
    sprotocol_device_t devices[SPROTOCOL_MAX_SLAVES];

    /* 黑名单 */
    sprotocol_blacklist_entry_t blacklist[SPROTOCOL_MAX_BLACKLIST];
    uint8_t blacklist_count;

    /* 错误计数（窗口期内 CRC/SEQ/MAC 错误） */
    struct {
        uint8_t  addr;          /* 0 表示槽位空闲 */
        uint16_t err_count;
        uint32_t window_start;
    } err_track[SPROTOCOL_MAX_BLACKLIST];

    /* 序列号上次保存时间 */
    uint32_t last_seq_save_ms;

    /* 加密 */
    spc_keypair_t ecc;
    peer_crypto_t peers[SPROTOCOL_MAX_SLAVES];
};

/* ============================================================ */
/* 工具函数                                                     */
/* ============================================================ */

static uint32_t now_ms(sprotocol_handle_t h)
{
    return h->cfg.get_time ? h->cfg.get_time() : 0;
}

static int dev_idx_for(sprotocol_handle_t h, uint8_t addr)
{
    if (h->cfg.role == SPROTOCOL_ROLE_MASTER) {
        uint8_t max_addr = (uint8_t)(SPROTOCOL_MIN_SLAVE_ADDR + h->cfg.max_slaves - 1);
        if (addr < SPROTOCOL_MIN_SLAVE_ADDR || addr > max_addr) return -1;
        return addr - SPROTOCOL_MIN_SLAVE_ADDR;
    } else {
        return (addr == SPROTOCOL_ADDR_MASTER) ? 0 : -1;
    }
}

static uint8_t pack_flags(sprotocol_flags_t f)
{
    uint8_t b = 0;
    if (f.broadcast)  b |= 1u << 0;
    if (f.need_ack)   b |= 1u << 1;
    if (f.encrypted)  b |= 1u << 2;
    if (f.retransmit) b |= 1u << 3;
    if (f.fragmented) b |= 1u << 4;
    return b;
}

static sprotocol_flags_t unpack_flags(uint8_t b)
{
    sprotocol_flags_t f = {0};
    f.broadcast  = (b >> 0) & 1u;
    f.need_ack   = (b >> 1) & 1u;
    f.encrypted  = (b >> 2) & 1u;
    f.retransmit = (b >> 3) & 1u;
    f.fragmented = (b >> 4) & 1u;
    return f;
}

/* ============================================================ */
/* CRC16-CCITT-FALSE                                            */
/* ============================================================ */

uint16_t sprotocol_crc16(const uint8_t* data, size_t len)
{
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; ++i) {
        crc ^= (uint16_t)data[i] << 8;
        for (int b = 0; b < 8; ++b) {
            if (crc & 0x8000) crc = (uint16_t)((crc << 1) ^ 0x1021);
            else              crc = (uint16_t)(crc << 1);
        }
    }
    return crc;
}

/* ============================================================ */
/* 帧编/解码                                                    */
/* ============================================================ */

/* 把 frame 序列化成线缆字节，返回总长度，失败返回 0。 */
static size_t frame_encode(const sprotocol_frame_t* fr, uint8_t* buf, size_t bufcap)
{
    size_t total = WIRE_OVERHEAD + fr->payload_len;
    if (bufcap < total) return 0;

    buf[0] = SPROTOCOL_FRAME_HEADER;
    buf[1] = SPROTOCOL_FRAME_VERSION;
    buf[2] = pack_flags(fr->flags);
    buf[3] = fr->src_addr;
    buf[4] = fr->dest_addr;
    buf[5] = (uint8_t)(fr->seq & 0xFF);
    buf[6] = (uint8_t)((fr->seq >> 8) & 0xFF);
    buf[7] = (uint8_t)(fr->domain_id & 0xFF);
    buf[8] = (uint8_t)((fr->domain_id >> 8) & 0xFF);
    buf[9] = fr->msg_type;
    buf[10] = fr->payload_len;
    if (fr->payload_len) {
        memcpy(buf + WIRE_HEADER_LEN, fr->payload, fr->payload_len);
    }
    uint16_t crc = sprotocol_crc16(buf, WIRE_HEADER_LEN + fr->payload_len);
    buf[WIRE_HEADER_LEN + fr->payload_len + 0] = (uint8_t)(crc & 0xFF);
    buf[WIRE_HEADER_LEN + fr->payload_len + 1] = (uint8_t)((crc >> 8) & 0xFF);
    return total;
}

/* 解析单帧，返回消耗字节数；失败返回负错误码（按 SPROTOCOL_ERR_*）。
 * 若长度尚不完整返回 0 表示等待更多数据。 */
static int frame_decode(const uint8_t* buf, size_t len, sprotocol_frame_t* fr)
{
    if (len < WIRE_HEADER_LEN) return 0;
    if (buf[0] != SPROTOCOL_FRAME_HEADER) return SPROTOCOL_ERR_INVALID_ARG;
    if (buf[1] != SPROTOCOL_FRAME_VERSION) return SPROTOCOL_ERR_INVALID_ARG;
    uint8_t pl = buf[10];
    size_t total = WIRE_OVERHEAD + pl;
    if (len < total) return 0;

    uint16_t got = (uint16_t)buf[WIRE_HEADER_LEN + pl] |
                   ((uint16_t)buf[WIRE_HEADER_LEN + pl + 1] << 8);
    uint16_t want = sprotocol_crc16(buf, WIRE_HEADER_LEN + pl);
    if (got != want) return SPROTOCOL_ERR_CRC;

    fr->header     = buf[0];
    fr->version    = buf[1];
    fr->flags      = unpack_flags(buf[2]);
    fr->src_addr   = buf[3];
    fr->dest_addr  = buf[4];
    fr->seq        = (uint16_t)buf[5] | ((uint16_t)buf[6] << 8);
    fr->domain_id  = (uint16_t)buf[7] | ((uint16_t)buf[8] << 8);
    fr->msg_type   = buf[9];
    fr->payload_len = pl;
    if (pl) memcpy(fr->payload, buf + WIRE_HEADER_LEN, pl);
    fr->crc        = got;

    return (int)total;
}

/* ============================================================ */
/* 黑名单                                                        */
/* ============================================================ */

static int blacklist_find(sprotocol_handle_t h, uint8_t addr)
{
    for (uint8_t i = 0; i < h->blacklist_count; ++i) {
        if (h->blacklist[i].addr == addr) return i;
    }
    return -1;
}

static void blacklist_add(sprotocol_handle_t h, uint8_t addr, uint8_t trigger)
{
    if (blacklist_find(h, addr) >= 0) return;
    if (h->blacklist_count >= SPROTOCOL_MAX_BLACKLIST) return;
    uint32_t now = now_ms(h);
    sprotocol_blacklist_entry_t* e = &h->blacklist[h->blacklist_count++];
    e->addr = addr;
    e->add_time = now;
    e->expire_time = now + SPROTOCOL_BLACKLIST_EXPIRE;
    e->trigger_count = trigger;
}

static void blacklist_expire_check(sprotocol_handle_t h)
{
    uint32_t now = now_ms(h);
    for (uint8_t i = 0; i < h->blacklist_count;) {
        if ((int32_t)(now - h->blacklist[i].expire_time) >= 0) {
            for (uint8_t j = i + 1; j < h->blacklist_count; ++j) {
                h->blacklist[j - 1] = h->blacklist[j];
            }
            h->blacklist_count--;
        } else {
            ++i;
        }
    }
}

static void err_track_bump(sprotocol_handle_t h, uint8_t addr)
{
    uint32_t now = now_ms(h);
    int slot = -1;
    int empty = -1;
    for (int i = 0; i < SPROTOCOL_MAX_BLACKLIST; ++i) {
        if (h->err_track[i].addr == addr && h->err_track[i].addr != 0) { slot = i; break; }
        if (h->err_track[i].addr == 0 && empty < 0) empty = i;
    }
    if (slot < 0) {
        if (empty < 0) return;  /* 满了就放弃跟踪，不影响正常流程 */
        slot = empty;
        h->err_track[slot].addr = addr;
        h->err_track[slot].err_count = 0;
        h->err_track[slot].window_start = now;
    }
    /* 窗口过期则重置 */
    if ((uint32_t)(now - h->err_track[slot].window_start) > SPROTOCOL_BLACKLIST_WINDOW) {
        h->err_track[slot].window_start = now;
        h->err_track[slot].err_count = 0;
    }
    h->err_track[slot].err_count++;
    if (h->err_track[slot].err_count >= SPROTOCOL_BLACKLIST_LIMIT) {
        blacklist_add(h, addr, (uint8_t)h->err_track[slot].err_count);
        h->err_track[slot].addr = 0;  /* 清理跟踪槽 */
    }
}

/* ============================================================ */
/* 设备/在线状态                                                */
/* ============================================================ */

static void mark_online(sprotocol_handle_t h, int idx)
{
    sprotocol_device_t* d = &h->devices[idx];
    uint8_t was = d->online;
    d->online = SPROTOCOL_DEVICE_ONLINE;
    d->last_heartbeat = now_ms(h);
    if (!was && h->cfg.online_cb) {
        pthread_mutex_unlock(&h->lock);
        h->cfg.online_cb(d->addr, 1, h->cfg.user_data);
        pthread_mutex_lock(&h->lock);
    }
}

static void mark_offline_locked(sprotocol_handle_t h, int idx)
{
    sprotocol_device_t* d = &h->devices[idx];
    if (d->online != SPROTOCOL_DEVICE_OFFLINE) {
        d->online = SPROTOCOL_DEVICE_OFFLINE;
        if (h->cfg.online_cb) {
            uint8_t addr = d->addr;
            pthread_mutex_unlock(&h->lock);
            h->cfg.online_cb(addr, 0, h->cfg.user_data);
            pthread_mutex_lock(&h->lock);
        }
    }
}

/* ============================================================ */
/* 加密 / 解密辅助                                              */
/* ============================================================ */

static void build_iv(uint8_t iv[SPC_AES_BLOCK_LEN],
                     const uint8_t nonce_base[SPC_NONCE_BASE_LEN],
                     uint16_t seq, uint8_t src, uint8_t dst)
{
    memcpy(iv, nonce_base, SPC_NONCE_BASE_LEN);
    iv[SPC_NONCE_BASE_LEN + 0] = (uint8_t)(seq & 0xFF);
    iv[SPC_NONCE_BASE_LEN + 1] = (uint8_t)((seq >> 8) & 0xFF);
    iv[SPC_NONCE_BASE_LEN + 2] = src;
    iv[SPC_NONCE_BASE_LEN + 3] = dst;
    /* 末尾 4 字节为计数器（CTR 块计数），从 0 开始 */
    iv[12] = iv[13] = iv[14] = iv[15] = 0;
}

/* ============================================================ */
/* 帧发送（带可选加密）                                          */
/* ============================================================ */

static int dispatch_send(sprotocol_handle_t h, sprotocol_frame_t* fr)
{
    uint8_t buf[WIRE_MAX_LEN];
    size_t n = frame_encode(fr, buf, sizeof(buf));
    if (!n) return SPROTOCOL_ERR_INVALID_ARG;
    if (!h->cfg.send_cb) return SPROTOCOL_ERR_INVALID_STATE;
    pthread_mutex_unlock(&h->lock);
    h->cfg.send_cb(buf, n, h->cfg.user_data);
    pthread_mutex_lock(&h->lock);
    return SPROTOCOL_OK;
}

/* 尝试加密：成功后 fr->payload/payload_len 被替换为密文；失败保持原样 */
static int maybe_encrypt(sprotocol_handle_t h, sprotocol_frame_t* fr,
                         const uint8_t* plain, size_t plain_len, int peer_idx)
{
    if (!h->cfg.encryption_enabled || h->cfg.enc_type != SPROTOCOL_ENC_ECC ||
        peer_idx < 0 || !h->peers[peer_idx].sess.ready ||
        fr->msg_type == SPROTOCOL_MSG_PAIR_REQ ||
        fr->msg_type == SPROTOCOL_MSG_PAIR_RSP ||
        fr->msg_type == SPROTOCOL_MSG_PAIR_CFM ||
        fr->flags.broadcast) {
        if (plain_len > SPROTOCOL_MAX_PAYLOAD_LEN) return SPROTOCOL_ERR_INVALID_ARG;
        if (plain_len) memcpy(fr->payload, plain, plain_len);
        fr->payload_len = (uint8_t)plain_len;
        fr->flags.encrypted = 0;
        return SPROTOCOL_OK;
    }
    if (plain_len + ENC_OVERHEAD > SPROTOCOL_MAX_PAYLOAD_LEN) return SPROTOCOL_ERR_INVALID_ARG;

    spc_session_t* sess = &h->peers[peer_idx].sess;
    uint8_t* nonce = fr->payload;                                   /* 12B */
    uint8_t* ct    = fr->payload + SPC_FRAME_NONCE_LEN;             /* L  */
    uint8_t* tag   = fr->payload + SPC_FRAME_NONCE_LEN + plain_len; /* 8B */

    if (spc_random_bytes(nonce, SPC_FRAME_NONCE_LEN) != 0) return SPROTOCOL_ERR_CRYPTO;

    uint8_t iv[SPC_AES_BLOCK_LEN];
    build_iv(iv, sess->nonce_base, fr->seq, fr->src_addr, fr->dest_addr);
    /* 叠加随机 nonce 以进一步降低冲突概率 */
    for (int i = 0; i < SPC_FRAME_NONCE_LEN; ++i) iv[i] ^= nonce[i];

    if (spc_aes_ctr_xcrypt(sess, iv, plain, ct, plain_len) != 0)
        return SPROTOCOL_ERR_CRYPTO;

    /* MAC 输入 = header(11B 不含 CRC，但 payload_len 字段先写为 enc_len) || nonce || ciphertext */
    uint8_t enc_len = (uint8_t)(SPC_FRAME_NONCE_LEN + plain_len + SPC_HMAC_TAG_LEN);
    uint8_t hdr[WIRE_HEADER_LEN];
    hdr[0] = SPROTOCOL_FRAME_HEADER;
    hdr[1] = SPROTOCOL_FRAME_VERSION;
    sprotocol_flags_t f = fr->flags; f.encrypted = 1;
    hdr[2] = pack_flags(f);
    hdr[3] = fr->src_addr;
    hdr[4] = fr->dest_addr;
    hdr[5] = (uint8_t)(fr->seq & 0xFF);
    hdr[6] = (uint8_t)((fr->seq >> 8) & 0xFF);
    hdr[7] = (uint8_t)(fr->domain_id & 0xFF);
    hdr[8] = (uint8_t)((fr->domain_id >> 8) & 0xFF);
    hdr[9] = fr->msg_type;
    hdr[10] = enc_len;

    uint8_t mac_in[WIRE_HEADER_LEN + SPC_FRAME_NONCE_LEN + SPROTOCOL_MAX_PAYLOAD_LEN];
    memcpy(mac_in,                         hdr,   WIRE_HEADER_LEN);
    memcpy(mac_in + WIRE_HEADER_LEN,       nonce, SPC_FRAME_NONCE_LEN);
    memcpy(mac_in + WIRE_HEADER_LEN + SPC_FRAME_NONCE_LEN, ct, plain_len);

    uint8_t full_tag[32];
    if (spc_hmac_sha256(sess, mac_in,
                        WIRE_HEADER_LEN + SPC_FRAME_NONCE_LEN + plain_len,
                        full_tag) != 0) {
        return SPROTOCOL_ERR_CRYPTO;
    }
    memcpy(tag, full_tag, SPC_HMAC_TAG_LEN);

    fr->payload_len = enc_len;
    fr->flags.encrypted = 1;
    return SPROTOCOL_OK;
}

/* 解密入站帧；成功后 plain_buf/plain_len 给出明文（指向 fr->payload 内偏移） */
static int try_decrypt(sprotocol_handle_t h, sprotocol_frame_t* fr,
                       int peer_idx, uint8_t** plain_buf, size_t* plain_len)
{
    if (peer_idx < 0 || !h->peers[peer_idx].sess.ready) return SPROTOCOL_ERR_CRYPTO;
    if (fr->payload_len < ENC_OVERHEAD) return SPROTOCOL_ERR_CRYPTO;

    spc_session_t* sess = &h->peers[peer_idx].sess;
    size_t L = fr->payload_len - ENC_OVERHEAD;
    uint8_t* nonce = fr->payload;
    uint8_t* ct    = fr->payload + SPC_FRAME_NONCE_LEN;
    uint8_t* tag   = fr->payload + SPC_FRAME_NONCE_LEN + L;

    /* 先校验 MAC */
    uint8_t hdr[WIRE_HEADER_LEN];
    hdr[0] = SPROTOCOL_FRAME_HEADER;
    hdr[1] = SPROTOCOL_FRAME_VERSION;
    hdr[2] = pack_flags(fr->flags);
    hdr[3] = fr->src_addr;
    hdr[4] = fr->dest_addr;
    hdr[5] = (uint8_t)(fr->seq & 0xFF);
    hdr[6] = (uint8_t)((fr->seq >> 8) & 0xFF);
    hdr[7] = (uint8_t)(fr->domain_id & 0xFF);
    hdr[8] = (uint8_t)((fr->domain_id >> 8) & 0xFF);
    hdr[9] = fr->msg_type;
    hdr[10] = fr->payload_len;

    uint8_t mac_in[WIRE_HEADER_LEN + SPC_FRAME_NONCE_LEN + SPROTOCOL_MAX_PAYLOAD_LEN];
    memcpy(mac_in,                       hdr,   WIRE_HEADER_LEN);
    memcpy(mac_in + WIRE_HEADER_LEN,     nonce, SPC_FRAME_NONCE_LEN);
    memcpy(mac_in + WIRE_HEADER_LEN + SPC_FRAME_NONCE_LEN, ct, L);

    uint8_t full_tag[32];
    if (spc_hmac_sha256(sess, mac_in,
                        WIRE_HEADER_LEN + SPC_FRAME_NONCE_LEN + L,
                        full_tag) != 0) return SPROTOCOL_ERR_CRYPTO;
    if (spc_consttime_memcmp(full_tag, tag, SPC_HMAC_TAG_LEN) != 0)
        return SPROTOCOL_ERR_CRYPTO;

    /* 再解密 */
    uint8_t iv[SPC_AES_BLOCK_LEN];
    build_iv(iv, sess->nonce_base, fr->seq, fr->src_addr, fr->dest_addr);
    for (int i = 0; i < SPC_FRAME_NONCE_LEN; ++i) iv[i] ^= nonce[i];

    static uint8_t plain[SPROTOCOL_MAX_PAYLOAD_LEN]; /* 不可重入；由 handle lock 保护 */
    if (spc_aes_ctr_xcrypt(sess, iv, ct, plain, L) != 0) return SPROTOCOL_ERR_CRYPTO;

    *plain_buf = plain;
    *plain_len = L;
    return SPROTOCOL_OK;
}

/* ============================================================ */
/* 帧入站处理                                                   */
/* ============================================================ */

static void notify_pair_locked(sprotocol_handle_t h, uint8_t addr, uint8_t status)
{
    if (!h->cfg.pair_cb) return;
    pthread_mutex_unlock(&h->lock);
    h->cfg.pair_cb(addr, status, h->cfg.user_data);
    pthread_mutex_lock(&h->lock);
}

static void notify_recv_locked(sprotocol_handle_t h, uint8_t src, uint16_t domain,
                               uint8_t msg_type, const uint8_t* p, size_t l)
{
    if (!h->cfg.recv_cb) return;
    pthread_mutex_unlock(&h->lock);
    h->cfg.recv_cb(src, domain, msg_type, p, l, h->cfg.user_data);
    pthread_mutex_lock(&h->lock);
}

static int build_and_send(sprotocol_handle_t h, uint8_t dest, uint16_t domain,
                          uint8_t msg_type, const uint8_t* payload, size_t len,
                          int allow_encrypt)
{
    sprotocol_frame_t fr;
    memset(&fr, 0, sizeof(fr));
    fr.header = SPROTOCOL_FRAME_HEADER;
    fr.version = SPROTOCOL_FRAME_VERSION;
    fr.src_addr = h->cfg.local_addr;
    fr.dest_addr = dest;
    fr.domain_id = domain;
    fr.msg_type = msg_type;
    fr.flags.broadcast = (dest == SPROTOCOL_ADDR_BROADCAST) ? 1 : 0;

    int peer_idx = dev_idx_for(h, dest);
    if (peer_idx >= 0) {
        h->devices[peer_idx].seq_tx++;
        fr.seq = h->devices[peer_idx].seq_tx;
    } else {
        /* 广播或非法目标：使用 master/slave 公共递增的简易序号 */
        static _Thread_local uint16_t bcast_seq = 0;
        bcast_seq++;
        fr.seq = bcast_seq;
    }

    int rc = SPROTOCOL_OK;
    if (allow_encrypt) {
        rc = maybe_encrypt(h, &fr, payload, len, peer_idx);
    } else {
        if (len) memcpy(fr.payload, payload, len);
        fr.payload_len = (uint8_t)len;
    }
    if (rc != SPROTOCOL_OK) return rc;
    return dispatch_send(h, &fr);
}

/* ---------- 配对处理 ---------- */

static int slot_occupy_master(sprotocol_handle_t h, uint8_t slave_addr)
{
    int idx = dev_idx_for(h, slave_addr);
    if (idx < 0) return -1;
    if (h->devices[idx].pair_status == SPROTOCOL_PAIR_NONE) {
        memset(&h->devices[idx], 0, sizeof(h->devices[idx]));
        h->devices[idx].addr = slave_addr;
    }
    return idx;
}

static int slot_occupy_slave(sprotocol_handle_t h)
{
    if (h->devices[0].pair_status == SPROTOCOL_PAIR_NONE) {
        memset(&h->devices[0], 0, sizeof(h->devices[0]));
        h->devices[0].addr = SPROTOCOL_ADDR_MASTER;
    }
    return 0;
}

static int handle_pair_req(sprotocol_handle_t h, sprotocol_frame_t* fr)
{
    if (h->cfg.role != SPROTOCOL_ROLE_SLAVE) return SPROTOCOL_ERR_INVALID_STATE;
    if (fr->payload_len != SPC_ECC_PUB_LEN) return SPROTOCOL_ERR_INVALID_ARG;

    int idx = slot_occupy_slave(h);
    sprotocol_device_t* d = &h->devices[idx];
    d->pair_status = SPROTOCOL_PAIR_PENDING;
    d->pair_time = now_ms(h);
    d->seq_rx = fr->seq;

    /* 派生会话 */
    spc_session_free(&h->peers[idx].sess);
    if (spc_session_derive(&h->peers[idx].sess, &h->ecc,
                           fr->payload, fr->payload_len,
                           (const uint8_t*)HANDSHAKE_INFO,
                           sizeof(HANDSHAKE_INFO) - 1) != 0) {
        d->pair_status = SPROTOCOL_PAIR_NONE;
        return SPROTOCOL_ERR_CRYPTO;
    }
    notify_pair_locked(h, fr->src_addr, SPROTOCOL_PAIR_PENDING);

    /* 回复 PAIR_RSP，载荷 = 自己的公钥 */
    return build_and_send(h, fr->src_addr, SPROTOCOL_DOMAIN_BASE,
                          SPROTOCOL_MSG_PAIR_RSP,
                          h->ecc.pub, SPC_ECC_PUB_LEN, 0);
}

static int handle_pair_rsp(sprotocol_handle_t h, sprotocol_frame_t* fr)
{
    if (h->cfg.role != SPROTOCOL_ROLE_MASTER) return SPROTOCOL_ERR_INVALID_STATE;
    if (fr->payload_len != SPC_ECC_PUB_LEN) return SPROTOCOL_ERR_INVALID_ARG;
    int idx = dev_idx_for(h, fr->src_addr);
    if (idx < 0) return SPROTOCOL_ERR_INVALID_ARG;
    sprotocol_device_t* d = &h->devices[idx];
    if (d->pair_status != SPROTOCOL_PAIR_PENDING) return SPROTOCOL_ERR_INVALID_STATE;

    spc_session_free(&h->peers[idx].sess);
    if (spc_session_derive(&h->peers[idx].sess, &h->ecc,
                           fr->payload, fr->payload_len,
                           (const uint8_t*)HANDSHAKE_INFO,
                           sizeof(HANDSHAKE_INFO) - 1) != 0) {
        d->pair_status = SPROTOCOL_PAIR_NONE;
        notify_pair_locked(h, fr->src_addr, SPROTOCOL_PAIR_NONE);
        return SPROTOCOL_ERR_CRYPTO;
    }

    /* 用会话密钥计算 confirm tag = HMAC(mac_key, "sprotocol-confirm" || master_pub || slave_pub) */
    uint8_t mac_in[17 + 2 * SPC_ECC_PUB_LEN];
    memcpy(mac_in, "sprotocol-confirm", 17);
    memcpy(mac_in + 17, h->ecc.pub, SPC_ECC_PUB_LEN);
    memcpy(mac_in + 17 + SPC_ECC_PUB_LEN, fr->payload, SPC_ECC_PUB_LEN);
    uint8_t tag[32];
    if (spc_hmac_sha256(&h->peers[idx].sess, mac_in, sizeof(mac_in), tag) != 0) {
        return SPROTOCOL_ERR_CRYPTO;
    }

    int rc = build_and_send(h, fr->src_addr, SPROTOCOL_DOMAIN_BASE,
                            SPROTOCOL_MSG_PAIR_CFM, tag, sizeof(tag), 0);
    if (rc != SPROTOCOL_OK) return rc;

    d->pair_status = SPROTOCOL_PAIR_COMPLETE;
    d->seq_rx = fr->seq;
    mark_online(h, idx);
    notify_pair_locked(h, fr->src_addr, SPROTOCOL_PAIR_COMPLETE);
    return SPROTOCOL_OK;
}

static int handle_pair_cfm(sprotocol_handle_t h, sprotocol_frame_t* fr)
{
    if (h->cfg.role != SPROTOCOL_ROLE_SLAVE) return SPROTOCOL_ERR_INVALID_STATE;
    if (fr->payload_len != 32) return SPROTOCOL_ERR_INVALID_ARG;
    int idx = dev_idx_for(h, fr->src_addr);
    if (idx < 0) return SPROTOCOL_ERR_INVALID_ARG;
    sprotocol_device_t* d = &h->devices[idx];
    if (d->pair_status != SPROTOCOL_PAIR_PENDING) return SPROTOCOL_ERR_INVALID_STATE;
    if (!h->peers[idx].sess.ready) return SPROTOCOL_ERR_INVALID_STATE;

    /* 重算 confirm tag 与对端发来的 32 字节 HMAC 对比 */
    uint8_t mac_in[17 + 2 * SPC_ECC_PUB_LEN];
    memcpy(mac_in, "sprotocol-confirm", 17);
    memcpy(mac_in + 17, h->peers[idx].sess.peer_pub, SPC_ECC_PUB_LEN); /* master_pub */
    memcpy(mac_in + 17 + SPC_ECC_PUB_LEN, h->ecc.pub, SPC_ECC_PUB_LEN); /* slave_pub */

    uint8_t tag[32];
    if (spc_hmac_sha256(&h->peers[idx].sess, mac_in, sizeof(mac_in), tag) != 0) {
        return SPROTOCOL_ERR_CRYPTO;
    }
    if (spc_consttime_memcmp(tag, fr->payload, 32) != 0) {
        err_track_bump(h, fr->src_addr);
        return SPROTOCOL_ERR_CRYPTO;
    }

    d->pair_status = SPROTOCOL_PAIR_COMPLETE;
    d->seq_rx = fr->seq;
    mark_online(h, idx);
    notify_pair_locked(h, fr->src_addr, SPROTOCOL_PAIR_COMPLETE);
    return SPROTOCOL_OK;
}

/* ---------- 数据/心跳 ---------- */

static int handle_heartbeat(sprotocol_handle_t h, sprotocol_frame_t* fr)
{
    int idx = dev_idx_for(h, fr->src_addr);
    if (idx < 0) return SPROTOCOL_ERR_INVALID_ARG;
    if (h->devices[idx].pair_status != SPROTOCOL_PAIR_COMPLETE) return SPROTOCOL_ERR_INVALID_STATE;
    mark_online(h, idx);
    return SPROTOCOL_OK;
}

static void deliver_data(sprotocol_handle_t h, sprotocol_frame_t* fr,
                         int peer_idx, uint8_t* plain, size_t plain_len)
{
    if (peer_idx >= 0) {
        h->devices[peer_idx].seq_rx = fr->seq;
        mark_online(h, peer_idx);
    }
    notify_recv_locked(h, fr->src_addr, fr->domain_id, fr->msg_type, plain, plain_len);
}

/* ============================================================ */
/* 公共 API                                                     */
/* ============================================================ */

const char* sprotocol_get_version(void)
{
    return "1.0.0";
}

sprotocol_handle_t sprotocol_init(const sprotocol_config_t* cfg)
{
    if (!cfg) return NULL;
    if (cfg->role == SPROTOCOL_ROLE_MASTER) {
        if (cfg->local_addr != SPROTOCOL_ADDR_MASTER) return NULL;
        if (cfg->max_slaves == 0 || cfg->max_slaves > SPROTOCOL_MAX_SLAVES) return NULL;
    } else {
        if (cfg->local_addr < SPROTOCOL_MIN_SLAVE_ADDR ||
            cfg->local_addr > SPROTOCOL_MAX_SLAVE_ADDR) return NULL;
    }
    if (spc_global_init() != 0) return NULL;

    sprotocol_handle_t h = calloc(1, sizeof(*h));
    if (!h) return NULL;
    h->cfg = *cfg;
    if (h->cfg.heartbeat_timeout == 0) h->cfg.heartbeat_timeout = 3000;
    if (h->cfg.pair_timeout == 0)      h->cfg.pair_timeout = 5000;

    pthread_mutexattr_t a;
    pthread_mutexattr_init(&a);
    pthread_mutexattr_settype(&a, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&h->lock, &a);
    pthread_mutexattr_destroy(&a);

    if (spc_keypair_generate(&h->ecc) != 0) {
        pthread_mutex_destroy(&h->lock);
        free(h);
        return NULL;
    }
    return h;
}

void sprotocol_deinit(sprotocol_handle_t h)
{
    if (!h) return;
    pthread_mutex_lock(&h->lock);
    for (int i = 0; i < SPROTOCOL_MAX_SLAVES; ++i) {
        spc_session_free(&h->peers[i].sess);
    }
    spc_keypair_free(&h->ecc);
    pthread_mutex_unlock(&h->lock);
    pthread_mutex_destroy(&h->lock);
    free(h);
}

void sprotocol_poll(sprotocol_handle_t h)
{
    if (!h) return;
    pthread_mutex_lock(&h->lock);

    uint32_t now = now_ms(h);

    /* 心跳 / 配对超时 */
    int slot_count = (h->cfg.role == SPROTOCOL_ROLE_MASTER) ? h->cfg.max_slaves : 1;
    for (int i = 0; i < slot_count; ++i) {
        sprotocol_device_t* d = &h->devices[i];
        if (d->pair_status == SPROTOCOL_PAIR_PENDING) {
            if ((uint32_t)(now - d->pair_time) >= h->cfg.pair_timeout) {
                uint8_t addr = d->addr;
                spc_session_free(&h->peers[i].sess);
                memset(d, 0, sizeof(*d));
                notify_pair_locked(h, addr, SPROTOCOL_PAIR_NONE);
            }
        } else if (d->pair_status == SPROTOCOL_PAIR_COMPLETE) {
            if (d->online == SPROTOCOL_DEVICE_ONLINE &&
                (uint32_t)(now - d->last_heartbeat) >= h->cfg.heartbeat_timeout) {
                mark_offline_locked(h, i);
            }
        }
    }

    /* 黑名单过期 */
    blacklist_expire_check(h);

    /* 序列号周期保存 */
    if (h->cfg.flash_write && h->cfg.seq_save_interval > 0 &&
        (uint32_t)(now - h->last_seq_save_ms) >= h->cfg.seq_save_interval) {
        uint8_t buf[SPROTOCOL_MAX_SLAVES * 2];
        for (int i = 0; i < SPROTOCOL_MAX_SLAVES; ++i) {
            buf[i * 2 + 0] = (uint8_t)(h->devices[i].seq_tx & 0xFF);
            buf[i * 2 + 1] = (uint8_t)((h->devices[i].seq_tx >> 8) & 0xFF);
        }
        h->cfg.flash_write(0, buf, sizeof(buf), h->cfg.user_data);
        h->last_seq_save_ms = now;
    }

    pthread_mutex_unlock(&h->lock);
}

void sprotocol_input(sprotocol_handle_t h, const uint8_t* data, size_t len)
{
    if (!h || !data || len == 0) return;
    pthread_mutex_lock(&h->lock);

    size_t off = 0;
    while (off < len) {
        if (data[off] != SPROTOCOL_FRAME_HEADER) { off++; continue; }
        sprotocol_frame_t fr;
        int rc = frame_decode(data + off, len - off, &fr);
        if (rc == 0) break;                     /* 不完整，等下次 */
        if (rc < 0) {
            if (rc == SPROTOCOL_ERR_CRC) err_track_bump(h, data[off + 3]);
            off++;                               /* 跳过该字节继续扫 */
            continue;
        }

        /* 黑名单过滤 */
        if (blacklist_find(h, fr.src_addr) >= 0) {
            off += (size_t)rc;
            continue;
        }
        /* 地址过滤 */
        if (fr.dest_addr != h->cfg.local_addr &&
            fr.dest_addr != SPROTOCOL_ADDR_BROADCAST) {
            off += (size_t)rc;
            continue;
        }

        int peer_idx = dev_idx_for(h, fr.src_addr);

        /* 序列号检查（仅对配对完成且非配对/非广播帧） */
        if (peer_idx >= 0 &&
            h->devices[peer_idx].pair_status == SPROTOCOL_PAIR_COMPLETE &&
            !fr.flags.broadcast &&
            fr.msg_type != SPROTOCOL_MSG_PAIR_REQ &&
            fr.msg_type != SPROTOCOL_MSG_PAIR_RSP &&
            fr.msg_type != SPROTOCOL_MSG_PAIR_CFM) {
            uint16_t prev = h->devices[peer_idx].seq_rx;
            uint16_t cur = fr.seq;
            int ok = 0;
            if (cur > prev) ok = 1;
            /* 简单回绕：cur 很小且 prev 很大时允许 */
            else if (prev > 0xFF00 && cur < 0x00FF) ok = 1;
            if (!ok) {
                err_track_bump(h, fr.src_addr);
                off += (size_t)rc;
                continue;
            }
        }

        /* 解密（如有） */
        uint8_t* plain_buf = NULL;
        size_t plain_len = 0;
        if (fr.flags.encrypted) {
            int drc = try_decrypt(h, &fr, peer_idx, &plain_buf, &plain_len);
            if (drc != SPROTOCOL_OK) {
                err_track_bump(h, fr.src_addr);
                off += (size_t)rc;
                continue;
            }
        } else {
            plain_buf = fr.payload;
            plain_len = fr.payload_len;
        }

        switch (fr.msg_type) {
        case SPROTOCOL_MSG_PAIR_REQ:
            /* slave 收到时 payload 是明文（master 公钥） */
            handle_pair_req(h, &fr);
            break;
        case SPROTOCOL_MSG_PAIR_RSP:
            handle_pair_rsp(h, &fr);
            break;
        case SPROTOCOL_MSG_PAIR_CFM:
            handle_pair_cfm(h, &fr);
            break;
        case SPROTOCOL_MSG_HEARTBEAT:
            handle_heartbeat(h, &fr);
            break;
        case SPROTOCOL_MSG_DATA:
        default:
            deliver_data(h, &fr, peer_idx, plain_buf, plain_len);
            break;
        }
        off += (size_t)rc;
    }

    pthread_mutex_unlock(&h->lock);
}

/* ---------- 配对管理 ---------- */

int sprotocol_pair_request(sprotocol_handle_t h, uint8_t slave_addr)
{
    if (!h) return SPROTOCOL_ERR_INVALID_ARG;
    if (h->cfg.role != SPROTOCOL_ROLE_MASTER) return SPROTOCOL_ERR_INVALID_STATE;
    pthread_mutex_lock(&h->lock);
    int idx = dev_idx_for(h, slave_addr);
    if (idx < 0) { pthread_mutex_unlock(&h->lock); return SPROTOCOL_ERR_INVALID_ARG; }
    if (blacklist_find(h, slave_addr) >= 0) {
        pthread_mutex_unlock(&h->lock); return SPROTOCOL_ERR_BLACKLIST;
    }
    /* 检查是否还有空位 */
    int valid_count = 0;
    for (int i = 0; i < h->cfg.max_slaves; ++i) {
        if (h->devices[i].pair_status != SPROTOCOL_PAIR_NONE) valid_count++;
    }
    if (h->devices[idx].pair_status == SPROTOCOL_PAIR_NONE && valid_count >= h->cfg.max_slaves) {
        pthread_mutex_unlock(&h->lock); return SPROTOCOL_ERR_FULL;
    }
    slot_occupy_master(h, slave_addr);
    h->devices[idx].pair_status = SPROTOCOL_PAIR_PENDING;
    h->devices[idx].pair_time = now_ms(h);

    notify_pair_locked(h, slave_addr, SPROTOCOL_PAIR_PENDING);
    int rc = build_and_send(h, slave_addr, SPROTOCOL_DOMAIN_BASE,
                            SPROTOCOL_MSG_PAIR_REQ,
                            h->ecc.pub, SPC_ECC_PUB_LEN, 0);
    pthread_mutex_unlock(&h->lock);
    return rc;
}

int sprotocol_remove_device(sprotocol_handle_t h, uint8_t addr)
{
    if (!h) return SPROTOCOL_ERR_INVALID_ARG;
    pthread_mutex_lock(&h->lock);
    int idx = dev_idx_for(h, addr);
    if (idx < 0 || h->devices[idx].pair_status == SPROTOCOL_PAIR_NONE) {
        pthread_mutex_unlock(&h->lock); return SPROTOCOL_ERR_NOT_FOUND;
    }
    spc_session_free(&h->peers[idx].sess);
    memset(&h->devices[idx], 0, sizeof(h->devices[idx]));
    notify_pair_locked(h, addr, SPROTOCOL_PAIR_NONE);
    pthread_mutex_unlock(&h->lock);
    return SPROTOCOL_OK;
}

void sprotocol_remove_all_devices(sprotocol_handle_t h)
{
    if (!h) return;
    pthread_mutex_lock(&h->lock);
    int slots = (h->cfg.role == SPROTOCOL_ROLE_MASTER) ? h->cfg.max_slaves : 1;
    for (int i = 0; i < slots; ++i) {
        if (h->devices[i].pair_status != SPROTOCOL_PAIR_NONE) {
            uint8_t addr = h->devices[i].addr;
            spc_session_free(&h->peers[i].sess);
            memset(&h->devices[i], 0, sizeof(h->devices[i]));
            notify_pair_locked(h, addr, SPROTOCOL_PAIR_NONE);
        }
    }
    pthread_mutex_unlock(&h->lock);
}

int sprotocol_get_paired_devices(sprotocol_handle_t h, uint8_t* addrs, uint8_t max_count)
{
    if (!h || !addrs) return 0;
    pthread_mutex_lock(&h->lock);
    int n = 0;
    int slots = (h->cfg.role == SPROTOCOL_ROLE_MASTER) ? h->cfg.max_slaves : 1;
    for (int i = 0; i < slots && n < max_count; ++i) {
        if (h->devices[i].pair_status == SPROTOCOL_PAIR_COMPLETE) {
            addrs[n++] = h->devices[i].addr;
        }
    }
    pthread_mutex_unlock(&h->lock);
    return n;
}

const sprotocol_device_t* sprotocol_get_device(sprotocol_handle_t h, uint8_t addr)
{
    if (!h) return NULL;
    pthread_mutex_lock(&h->lock);
    int idx = dev_idx_for(h, addr);
    const sprotocol_device_t* ret = NULL;
    if (idx >= 0 && h->devices[idx].pair_status != SPROTOCOL_PAIR_NONE) {
        ret = &h->devices[idx];
    }
    pthread_mutex_unlock(&h->lock);
    return ret;
}

/* ---------- 数据通信 ---------- */

int sprotocol_send(sprotocol_handle_t h, uint8_t dest, uint16_t domain,
                   uint8_t msg_type, const uint8_t* payload, size_t len)
{
    if (!h) return SPROTOCOL_ERR_INVALID_ARG;
    if (len > 0 && !payload) return SPROTOCOL_ERR_INVALID_ARG;
    if (len > SPROTOCOL_MAX_PAYLOAD_LEN) return SPROTOCOL_ERR_INVALID_ARG;
    pthread_mutex_lock(&h->lock);

    int idx = dev_idx_for(h, dest);
    if (idx < 0) { pthread_mutex_unlock(&h->lock); return SPROTOCOL_ERR_INVALID_ARG; }
    if (h->devices[idx].pair_status != SPROTOCOL_PAIR_COMPLETE) {
        pthread_mutex_unlock(&h->lock); return SPROTOCOL_ERR_INVALID_STATE;
    }
    if (blacklist_find(h, dest) >= 0) {
        pthread_mutex_unlock(&h->lock); return SPROTOCOL_ERR_BLACKLIST;
    }

    int rc = build_and_send(h, dest, domain, msg_type, payload, len, 1);
    pthread_mutex_unlock(&h->lock);
    return rc;
}

int sprotocol_broadcast(sprotocol_handle_t h, uint16_t domain,
                        uint8_t msg_type, const uint8_t* payload, size_t len)
{
    if (!h) return SPROTOCOL_ERR_INVALID_ARG;
    if (len > 0 && !payload) return SPROTOCOL_ERR_INVALID_ARG;
    if (len > SPROTOCOL_MAX_PAYLOAD_LEN) return SPROTOCOL_ERR_INVALID_ARG;
    pthread_mutex_lock(&h->lock);
    int rc = build_and_send(h, SPROTOCOL_ADDR_BROADCAST, domain,
                            msg_type, payload, len, 0);
    pthread_mutex_unlock(&h->lock);
    return rc;
}

/* ---------- 心跳 ---------- */

int sprotocol_send_heartbeat(sprotocol_handle_t h)
{
    if (!h) return SPROTOCOL_ERR_INVALID_ARG;
    if (h->cfg.role != SPROTOCOL_ROLE_SLAVE) return SPROTOCOL_ERR_INVALID_STATE;
    pthread_mutex_lock(&h->lock);
    if (h->devices[0].pair_status != SPROTOCOL_PAIR_COMPLETE) {
        pthread_mutex_unlock(&h->lock); return SPROTOCOL_ERR_INVALID_STATE;
    }
    int rc = build_and_send(h, SPROTOCOL_ADDR_MASTER, SPROTOCOL_DOMAIN_BASE,
                            SPROTOCOL_MSG_HEARTBEAT, NULL, 0, 0);
    pthread_mutex_unlock(&h->lock);
    return rc;
}

int sprotocol_is_device_online(sprotocol_handle_t h, uint8_t addr)
{
    if (!h) return 0;
    pthread_mutex_lock(&h->lock);
    int idx = dev_idx_for(h, addr);
    int on = 0;
    if (idx >= 0 && h->devices[idx].pair_status == SPROTOCOL_PAIR_COMPLETE) {
        on = (h->devices[idx].online == SPROTOCOL_DEVICE_ONLINE) ? 1 : 0;
    }
    pthread_mutex_unlock(&h->lock);
    return on;
}

/* ---------- 序列号 ---------- */

uint16_t sprotocol_get_tx_seq(sprotocol_handle_t h, uint8_t addr)
{
    if (!h) return 0;
    pthread_mutex_lock(&h->lock);
    int idx = dev_idx_for(h, addr);
    uint16_t s = 0;
    if (idx >= 0) s = h->devices[idx].seq_tx;
    pthread_mutex_unlock(&h->lock);
    return s;
}

void sprotocol_set_seq_save_interval(sprotocol_handle_t h, uint16_t interval_ms)
{
    if (!h) return;
    pthread_mutex_lock(&h->lock);
    h->cfg.seq_save_interval = interval_ms;
    pthread_mutex_unlock(&h->lock);
}

/* ---------- 黑名单 ---------- */

int sprotocol_is_blacklisted(sprotocol_handle_t h, uint8_t addr)
{
    if (!h) return 0;
    pthread_mutex_lock(&h->lock);
    int hit = blacklist_find(h, addr) >= 0 ? 1 : 0;
    pthread_mutex_unlock(&h->lock);
    return hit;
}

int sprotocol_get_blacklist_count(sprotocol_handle_t h)
{
    if (!h) return 0;
    pthread_mutex_lock(&h->lock);
    int c = h->blacklist_count;
    pthread_mutex_unlock(&h->lock);
    return c;
}
