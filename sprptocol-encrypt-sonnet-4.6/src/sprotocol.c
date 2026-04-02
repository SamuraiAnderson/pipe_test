#include "sprotocol.h"
#include "sprotocol_internal.h"
#include "sprotocol_crypto.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* =========================================================================
 * CRC-16/CCITT-FALSE  多项式 0x1021，初始值 0xFFFF，无反转
 * ========================================================================= */
uint16_t sprotocol_crc16(const uint8_t *data, size_t len) {
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint16_t)data[i] << 8;
        for (int j = 0; j < 8; j++) {
            if (crc & 0x8000)
                crc = (uint16_t)((crc << 1) ^ 0x1021);
            else
                crc <<= 1;
        }
    }
    return crc;
}

/* =========================================================================
 * 版本字符串
 * ========================================================================= */
const char* sprotocol_get_version(void) {
    return "1.0.0";
}

/* =========================================================================
 * 帧序列化
 * 将 sprotocol_frame_t 编码到字节缓冲区
 * 返回写入的总字节数，< 0 表示错误
 * ========================================================================= */
static int frame_encode(const sprotocol_frame_t *f, uint8_t *buf, size_t buf_len) {
    if (!f || !buf) return -1;
    size_t total = (size_t)(FRAME_HDR_SIZE + f->payload_len + FRAME_CRC_SIZE);
    if (buf_len < total) return -1;

    buf[0] = f->header;
    buf[1] = f->version;
    buf[2] = flags_to_byte(f->flags);
    buf[3] = f->src_addr;
    buf[4] = f->dest_addr;
    buf[5] = (uint8_t)(f->seq & 0xFF);
    buf[6] = (uint8_t)(f->seq >> 8);
    buf[7] = (uint8_t)(f->domain_id & 0xFF);
    buf[8] = (uint8_t)(f->domain_id >> 8);
    buf[9]  = f->msg_type;
    buf[10] = f->payload_len;
    if (f->payload_len > 0) {
        memcpy(buf + FRAME_HDR_SIZE, f->payload, f->payload_len);
    }
    uint16_t crc = sprotocol_crc16(buf, FRAME_HDR_SIZE + f->payload_len);
    buf[FRAME_HDR_SIZE + f->payload_len]     = (uint8_t)(crc & 0xFF);
    buf[FRAME_HDR_SIZE + f->payload_len + 1] = (uint8_t)(crc >> 8);
    return (int)total;
}

/* =========================================================================
 * 帧反序列化
 * 从字节缓冲区解码到 sprotocol_frame_t
 * 返回 SPROTOCOL_OK 或错误码
 * ========================================================================= */
static int frame_decode(const uint8_t *buf, size_t len, sprotocol_frame_t *f) {
    if (!buf || !f) return SPROTOCOL_ERR_INVALID_ARG;
    if (len < FRAME_MIN_SIZE) return SPROTOCOL_ERR_INVALID_ARG;

    if (buf[0] != SPROTOCOL_FRAME_HEADER) return SPROTOCOL_ERR_INVALID_ARG;

    uint8_t plen = buf[10];
    size_t expected = (size_t)(FRAME_HDR_SIZE + plen + FRAME_CRC_SIZE);
    if (len < expected) return SPROTOCOL_ERR_INVALID_ARG;

    /* CRC 校验 */
    uint16_t crc_recv = (uint16_t)(buf[FRAME_HDR_SIZE + plen]) |
                        ((uint16_t)(buf[FRAME_HDR_SIZE + plen + 1]) << 8);
    uint16_t crc_calc = sprotocol_crc16(buf, FRAME_HDR_SIZE + plen);
    if (crc_recv != crc_calc) return SPROTOCOL_ERR_CRC;

    f->header     = buf[0];
    f->version    = buf[1];
    f->flags      = byte_to_flags(buf[2]);
    f->src_addr   = buf[3];
    f->dest_addr  = buf[4];
    f->seq        = (uint16_t)(buf[5]) | ((uint16_t)(buf[6]) << 8);
    f->domain_id  = (uint16_t)(buf[7]) | ((uint16_t)(buf[8]) << 8);
    f->msg_type   = buf[9];
    f->payload_len = plen;
    if (plen > 0) {
        memcpy(f->payload, buf + FRAME_HDR_SIZE, plen);
    }
    f->crc = crc_recv;
    return SPROTOCOL_OK;
}

/* =========================================================================
 * 发送帧辅助（构建并通过 send_cb 发出）
 * ========================================================================= */
static int send_frame(struct sprotocol_handle *h, sprotocol_frame_t *f) {
    /* 若加密启用且密钥就绪，加密 payload */
    if (h->config.encryption_enabled && h->config.enc_type == SPROTOCOL_ENC_ECC) {
        int idx = find_slave_idx(h, f->dest_addr);
        if (idx >= 0 && h->peer_crypto[idx].ready &&
            f->msg_type == SPROTOCOL_MSG_DATA) {
            /* 使用 seq 低 16 字节作为 IV（简单方案） */
            uint8_t iv[SCRYPTO_IV_LEN];
            memset(iv, 0, sizeof(iv));
            iv[0] = (uint8_t)(f->seq & 0xFF);
            iv[1] = (uint8_t)(f->seq >> 8);
            iv[2] = f->src_addr;
            iv[3] = f->dest_addr;

            uint8_t enc_buf[SPROTOCOL_MAX_PAYLOAD_LEN];
            if (scrypto_aes_ctr_encrypt(h->peer_crypto[idx].shared_key,
                                         iv, f->payload, f->payload_len,
                                         enc_buf) == 0) {
                memcpy(f->payload, enc_buf, f->payload_len);
                f->flags.encrypted = 1;
            }
        }
    }

    uint8_t wire[FRAME_MAX_SIZE];
    int n = frame_encode(f, wire, sizeof(wire));
    if (n < 0) return SPROTOCOL_ERR_INVALID_ARG;

    if (h->config.send_cb) {
        h->config.send_cb(wire, (size_t)n, h->config.user_data);
    }
    return SPROTOCOL_OK;
}

/* =========================================================================
 * 黑名单检查/添加
 * ========================================================================= */
static int blacklist_check(struct sprotocol_handle *h, uint8_t addr) {
    uint32_t now = h->config.get_time ? h->config.get_time() : 0;
    for (int i = 0; i < h->blacklist_count; i++) {
        if (h->blacklist[i].addr == addr) {
            if (now - h->blacklist[i].add_time < h->blacklist[i].expire_time)
                return 1;
            /* 已过期，移除 */
            memmove(&h->blacklist[i], &h->blacklist[i + 1],
                    (size_t)(h->blacklist_count - i - 1) * sizeof(sprotocol_blacklist_entry_t));
            h->blacklist_count--;
            return 0;
        }
    }
    return 0;
}

__attribute__((unused))
static void blacklist_add(struct sprotocol_handle *h, uint8_t addr) {
    uint32_t now = h->config.get_time ? h->config.get_time() : 0;
    /* 已在黑名单则更新 */
    for (int i = 0; i < h->blacklist_count; i++) {
        if (h->blacklist[i].addr == addr) {
            h->blacklist[i].trigger_count++;
            h->blacklist[i].add_time = now;
            return;
        }
    }
    if (h->blacklist_count >= SPROTOCOL_MAX_BLACKLIST) return;
    sprotocol_blacklist_entry_t *e = &h->blacklist[h->blacklist_count++];
    e->addr          = addr;
    e->add_time      = now;
    e->expire_time   = SPROTOCOL_BLACKLIST_EXPIRE;
    e->trigger_count = 1;
}

/* =========================================================================
 * 配对消息处理
 * ========================================================================= */

/* 主机：发送 PAIR_CFM，完成配对 */
static void master_send_pair_cfm(struct sprotocol_handle *h, uint8_t slave_addr, int idx) {
    sprotocol_frame_t f;
    memset(&f, 0, sizeof(f));
    f.header      = SPROTOCOL_FRAME_HEADER;
    f.version     = SPROTOCOL_FRAME_VERSION;
    f.src_addr    = h->config.local_addr;
    f.dest_addr   = slave_addr;
    f.seq         = h->local_seq++;
    f.domain_id   = SPROTOCOL_DOMAIN_BASE;
    f.msg_type    = SPROTOCOL_MSG_PAIR_CFM;
    f.payload_len = 0;

    h->slaves[idx].pair_status = SPROTOCOL_PAIR_COMPLETE;
    h->slaves[idx].online      = SPROTOCOL_DEVICE_ONLINE;
    if (h->config.get_time) {
        h->slaves[idx].last_heartbeat = h->config.get_time();
    }
    h->pair_start_time[idx] = 0;

    send_frame(h, &f);

    if (h->config.pair_cb) {
        h->config.pair_cb(slave_addr, SPROTOCOL_PAIR_COMPLETE, h->config.user_data);
    }
}

/* 从机：收到 PAIR_REQ 后自动发送 PAIR_RSP */
static void slave_send_pair_rsp(struct sprotocol_handle *h, const sprotocol_frame_t *req) {
    /* 处理主机 ECC 公钥（若加密启用） */
    int idx = 0; /* 从机只有一个 master 条目 slaves[0] */
    if (h->config.encryption_enabled && h->config.enc_type == SPROTOCOL_ENC_ECC &&
        h->ecc_ctx && req->payload_len >= SCRYPTO_PUBKEY_LEN) {
        uint8_t derived_key[SCRYPTO_KEY_LEN];
        if (scrypto_derive_shared_key((scrypto_ctx_t*)h->ecc_ctx,
                                       req->payload, req->payload_len,
                                       derived_key) == 0) {
            memcpy(h->peer_crypto[idx].shared_key, derived_key, SCRYPTO_KEY_LEN);
            h->peer_crypto[idx].ready = 1;
        }
    }

    sprotocol_frame_t f;
    memset(&f, 0, sizeof(f));
    f.header   = SPROTOCOL_FRAME_HEADER;
    f.version  = SPROTOCOL_FRAME_VERSION;
    f.src_addr = h->config.local_addr;
    f.dest_addr = req->src_addr;
    f.seq       = h->local_seq++;
    f.domain_id = SPROTOCOL_DOMAIN_BASE;
    f.msg_type  = SPROTOCOL_MSG_PAIR_RSP;

    /* 将本机 ECC 公钥放入 payload（若加密启用） */
    if (h->config.encryption_enabled && h->config.enc_type == SPROTOCOL_ENC_ECC &&
        h->ecc_ctx && h->local_pubkey_len > 0) {
        memcpy(f.payload, h->local_pubkey, h->local_pubkey_len);
        f.payload_len = (uint8_t)h->local_pubkey_len;
    }

    /* 更新 master 信息（从机视角 slaves[0] 是主机） */
    h->slaves[idx].addr        = req->src_addr;
    h->slaves[idx].pair_status = SPROTOCOL_PAIR_PENDING;
    if (h->slave_count == 0) h->slave_count = 1;

    send_frame(h, &f);
}

/* 主机：收到 PAIR_RSP，派生共享密钥，发送 PAIR_CFM */
static void master_handle_pair_rsp(struct sprotocol_handle *h, const sprotocol_frame_t *rsp) {
    int idx = find_slave_idx(h, rsp->src_addr);
    if (idx < 0) return;
    if (h->slaves[idx].pair_status != SPROTOCOL_PAIR_PENDING) return;

    /* 派生共享密钥 */
    if (h->config.encryption_enabled && h->config.enc_type == SPROTOCOL_ENC_ECC &&
        h->ecc_ctx && rsp->payload_len >= SCRYPTO_PUBKEY_LEN) {
        uint8_t derived_key[SCRYPTO_KEY_LEN];
        if (scrypto_derive_shared_key((scrypto_ctx_t*)h->ecc_ctx,
                                       rsp->payload, rsp->payload_len,
                                       derived_key) == 0) {
            memcpy(h->peer_crypto[idx].shared_key, derived_key, SCRYPTO_KEY_LEN);
            h->peer_crypto[idx].ready = 1;
        }
    }

    master_send_pair_cfm(h, rsp->src_addr, idx);
}

/* 从机：收到 PAIR_CFM，配对完成 */
static void slave_handle_pair_cfm(struct sprotocol_handle *h, const sprotocol_frame_t *cfm) {
    int idx = find_slave_idx(h, cfm->src_addr);
    if (idx < 0) return;
    h->slaves[idx].pair_status = SPROTOCOL_PAIR_COMPLETE;
    h->slaves[idx].online      = SPROTOCOL_DEVICE_ONLINE;
    if (h->config.get_time) {
        h->slaves[idx].last_heartbeat = h->config.get_time();
    }
    if (h->config.pair_cb) {
        h->config.pair_cb(cfm->src_addr, SPROTOCOL_PAIR_COMPLETE, h->config.user_data);
    }
}

/* =========================================================================
 * 消息分发处理
 * ========================================================================= */
static void dispatch_frame(struct sprotocol_handle *h, const sprotocol_frame_t *f) {
    uint32_t now = h->config.get_time ? h->config.get_time() : 0;

    switch (f->msg_type) {
    case SPROTOCOL_MSG_PAIR_REQ:
        if (h->config.role == SPROTOCOL_ROLE_SLAVE) {
            slave_send_pair_rsp(h, f);
        }
        break;

    case SPROTOCOL_MSG_PAIR_RSP:
        if (h->config.role == SPROTOCOL_ROLE_MASTER) {
            master_handle_pair_rsp(h, f);
        }
        break;

    case SPROTOCOL_MSG_PAIR_CFM:
        if (h->config.role == SPROTOCOL_ROLE_SLAVE) {
            slave_handle_pair_cfm(h, f);
        }
        break;

    case SPROTOCOL_MSG_HEARTBEAT: {
        int idx = find_or_create_slave(h, f->src_addr);
        if (idx >= 0) {
            uint8_t was_online = h->slaves[idx].online;
            h->slaves[idx].online         = SPROTOCOL_DEVICE_ONLINE;
            h->slaves[idx].last_heartbeat = now;
            if (!was_online && h->config.online_cb) {
                h->config.online_cb(f->src_addr, SPROTOCOL_DEVICE_ONLINE,
                                    h->config.user_data);
            }
        }
        break;
    }

    case SPROTOCOL_MSG_DATA: {
        uint8_t payload[SPROTOCOL_MAX_PAYLOAD_LEN];
        size_t plen = f->payload_len;
        memcpy(payload, f->payload, plen);

        /* 若帧标记为加密，尝试解密 */
        if (f->flags.encrypted && h->config.encryption_enabled &&
            h->config.enc_type == SPROTOCOL_ENC_ECC) {
            int idx = find_slave_idx(h, f->src_addr);
            if (idx >= 0 && h->peer_crypto[idx].ready) {
                uint8_t iv[SCRYPTO_IV_LEN];
                memset(iv, 0, sizeof(iv));
                iv[0] = (uint8_t)(f->seq & 0xFF);
                iv[1] = (uint8_t)(f->seq >> 8);
                iv[2] = f->src_addr;
                iv[3] = f->dest_addr;
                scrypto_aes_ctr_decrypt(h->peer_crypto[idx].shared_key,
                                        iv, payload, plen, payload);
            }
        }

        if (h->config.recv_cb) {
            h->config.recv_cb(f->src_addr, f->domain_id, f->msg_type,
                              payload, plen, h->config.user_data);
        }
        break;
    }

    case SPROTOCOL_MSG_ACK:
    case SPROTOCOL_MSG_NACK:
        /* 简单 ACK/NACK，暂不处理重传逻辑 */
        break;

    default:
        /* 未知消息类型，传递给 recv_cb */
        if (h->config.recv_cb) {
            h->config.recv_cb(f->src_addr, f->domain_id, f->msg_type,
                              f->payload, f->payload_len, h->config.user_data);
        }
        break;
    }
}

/* =========================================================================
 * 公开 API 实现
 * ========================================================================= */

sprotocol_handle_t sprotocol_init(const sprotocol_config_t *config) {
    if (!config) return NULL;

    struct sprotocol_handle *h =
        (struct sprotocol_handle*)calloc(1, sizeof(struct sprotocol_handle));
    if (!h) return NULL;

    memcpy(&h->config, config, sizeof(sprotocol_config_t));

    /* 若未设置超时，使用默认值 */
    if (h->config.heartbeat_timeout == 0)
        h->config.heartbeat_timeout = 3000;
    if (h->config.pair_timeout == 0)
        h->config.pair_timeout = 5000;
    if (h->config.max_slaves == 0 || h->config.max_slaves > SPROTOCOL_MAX_SLAVES)
        h->config.max_slaves = SPROTOCOL_MAX_SLAVES;

    /* 初始化 ECC 上下文 */
    if (config->encryption_enabled && config->enc_type == SPROTOCOL_ENC_ECC) {
        h->ecc_ctx = scrypto_init();
        if (!h->ecc_ctx) {
            fprintf(stderr, "[sprotocol] ECC init failed\n");
            free(h);
            return NULL;
        }
        /* 导出本机公钥 */
        size_t pk_len = 0;
        if (scrypto_get_pubkey((scrypto_ctx_t*)h->ecc_ctx,
                                h->local_pubkey, sizeof(h->local_pubkey),
                                &pk_len) != 0) {
            fprintf(stderr, "[sprotocol] ECC get_pubkey failed\n");
            scrypto_free((scrypto_ctx_t*)h->ecc_ctx);
            free(h);
            return NULL;
        }
        h->local_pubkey_len = pk_len;
    }

    h->local_seq = 1;
    return (sprotocol_handle_t)h;
}

void sprotocol_deinit(sprotocol_handle_t handle) {
    struct sprotocol_handle *h = (struct sprotocol_handle*)handle;
    if (!h) return;
    if (h->ecc_ctx) {
        scrypto_free((scrypto_ctx_t*)h->ecc_ctx);
        h->ecc_ctx = NULL;
    }
    free(h);
}

void sprotocol_poll(sprotocol_handle_t handle) {
    struct sprotocol_handle *h = (struct sprotocol_handle*)handle;
    if (!h || !h->config.get_time) return;

    uint32_t now = h->config.get_time();

    for (int i = 0; i < h->slave_count; i++) {
        sprotocol_device_t *dev = &h->slaves[i];

        /* 心跳超时检测 */
        if (dev->online == SPROTOCOL_DEVICE_ONLINE &&
            dev->pair_status == SPROTOCOL_PAIR_COMPLETE &&
            h->config.heartbeat_timeout > 0) {
            uint32_t elapsed = now - dev->last_heartbeat;
            if (elapsed > h->config.heartbeat_timeout) {
                dev->online = SPROTOCOL_DEVICE_OFFLINE;
                if (h->config.online_cb) {
                    h->config.online_cb(dev->addr, SPROTOCOL_DEVICE_OFFLINE,
                                        h->config.user_data);
                }
            }
        }

        /* 配对超时检测 */
        if (dev->pair_status == SPROTOCOL_PAIR_PENDING &&
            h->pair_start_time[i] != 0) {
            uint32_t elapsed = now - h->pair_start_time[i];
            if (elapsed > h->config.pair_timeout) {
                dev->pair_status = SPROTOCOL_PAIR_NONE;
                h->pair_start_time[i] = 0;
                if (h->config.pair_cb) {
                    h->config.pair_cb(dev->addr, SPROTOCOL_PAIR_NONE,
                                      h->config.user_data);
                }
            }
        }
    }
}

void sprotocol_input(sprotocol_handle_t handle, const uint8_t *data, size_t len) {
    struct sprotocol_handle *h = (struct sprotocol_handle*)handle;
    if (!h || !data || len < FRAME_MIN_SIZE) return;

    sprotocol_frame_t f;
    int ret = frame_decode(data, len, &f);
    if (ret != SPROTOCOL_OK) {
        /* CRC 错误或格式错误，记录黑名单（对于恶意来源暂无地址信息，跳过） */
        return;
    }

    /* 检查目的地址是否匹配 */
    if (f.dest_addr != h->config.local_addr &&
        f.dest_addr != SPROTOCOL_ADDR_BROADCAST) {
        return;
    }

    /* 黑名单检查 */
    if (blacklist_check(h, f.src_addr)) {
        return;
    }

    /* 分发 */
    dispatch_frame(h, &f);
}

/* =========================================================================
 * 配对管理
 * ========================================================================= */

int sprotocol_pair_request(sprotocol_handle_t handle, uint8_t slave_addr) {
    struct sprotocol_handle *h = (struct sprotocol_handle*)handle;
    if (!h) return SPROTOCOL_ERR_INVALID_ARG;
    if (h->config.role != SPROTOCOL_ROLE_MASTER) return SPROTOCOL_ERR_INVALID_STATE;
    if (slave_addr < SPROTOCOL_MIN_SLAVE_ADDR || slave_addr > SPROTOCOL_MAX_SLAVE_ADDR)
        return SPROTOCOL_ERR_INVALID_ARG;
    if (blacklist_check(h, slave_addr)) return SPROTOCOL_ERR_BLACKLIST;

    int idx = find_or_create_slave(h, slave_addr);
    if (idx < 0) return SPROTOCOL_ERR_FULL;

    h->slaves[idx].pair_status = SPROTOCOL_PAIR_PENDING;
    h->pair_start_time[idx] = h->config.get_time ? h->config.get_time() : 0;

    sprotocol_frame_t f;
    memset(&f, 0, sizeof(f));
    f.header    = SPROTOCOL_FRAME_HEADER;
    f.version   = SPROTOCOL_FRAME_VERSION;
    f.src_addr  = h->config.local_addr;
    f.dest_addr = slave_addr;
    f.seq       = h->local_seq++;
    f.domain_id = SPROTOCOL_DOMAIN_BASE;
    f.msg_type  = SPROTOCOL_MSG_PAIR_REQ;

    /* 将本机 ECC 公钥放入 payload（若加密启用） */
    if (h->config.encryption_enabled && h->config.enc_type == SPROTOCOL_ENC_ECC &&
        h->ecc_ctx && h->local_pubkey_len > 0) {
        memcpy(f.payload, h->local_pubkey, h->local_pubkey_len);
        f.payload_len = (uint8_t)h->local_pubkey_len;
    }

    if (h->config.pair_cb) {
        h->config.pair_cb(slave_addr, SPROTOCOL_PAIR_PENDING, h->config.user_data);
    }

    return send_frame(h, &f);
}

int sprotocol_remove_device(sprotocol_handle_t handle, uint8_t addr) {
    struct sprotocol_handle *h = (struct sprotocol_handle*)handle;
    if (!h) return SPROTOCOL_ERR_INVALID_ARG;

    int idx = find_slave_idx(h, addr);
    if (idx < 0) return SPROTOCOL_ERR_NOT_FOUND;

    memmove(&h->slaves[idx], &h->slaves[idx + 1],
            (size_t)(h->slave_count - idx - 1) * sizeof(sprotocol_device_t));
    memmove(&h->peer_crypto[idx], &h->peer_crypto[idx + 1],
            (size_t)(h->slave_count - idx - 1) * sizeof(sprotocol_peer_crypto_t));
    memmove(&h->pair_start_time[idx], &h->pair_start_time[idx + 1],
            (size_t)(h->slave_count - idx - 1) * sizeof(uint32_t));
    h->slave_count--;
    return SPROTOCOL_OK;
}

void sprotocol_remove_all_devices(sprotocol_handle_t handle) {
    struct sprotocol_handle *h = (struct sprotocol_handle*)handle;
    if (!h) return;
    h->slave_count = 0;
    memset(h->slaves, 0, sizeof(h->slaves));
    memset(h->peer_crypto, 0, sizeof(h->peer_crypto));
    memset(h->pair_start_time, 0, sizeof(h->pair_start_time));
}

int sprotocol_get_paired_devices(sprotocol_handle_t handle, uint8_t *addrs, uint8_t max_count) {
    struct sprotocol_handle *h = (struct sprotocol_handle*)handle;
    if (!h || !addrs) return 0;

    int count = 0;
    for (int i = 0; i < h->slave_count && count < max_count; i++) {
        if (h->slaves[i].pair_status == SPROTOCOL_PAIR_COMPLETE) {
            addrs[count++] = h->slaves[i].addr;
        }
    }
    return count;
}

const sprotocol_device_t* sprotocol_get_device(sprotocol_handle_t handle, uint8_t addr) {
    struct sprotocol_handle *h = (struct sprotocol_handle*)handle;
    if (!h) return NULL;

    int idx = find_slave_idx(h, addr);
    if (idx < 0) return NULL;
    return &h->slaves[idx];
}

/* =========================================================================
 * 数据通信
 * ========================================================================= */

int sprotocol_send(sprotocol_handle_t handle, uint8_t dest_addr, uint16_t domain_id,
                   uint8_t msg_type, const uint8_t *payload, size_t len) {
    struct sprotocol_handle *h = (struct sprotocol_handle*)handle;
    if (!h) return SPROTOCOL_ERR_INVALID_ARG;
    if (len > SPROTOCOL_MAX_PAYLOAD_LEN) return SPROTOCOL_ERR_INVALID_ARG;
    if (blacklist_check(h, dest_addr)) return SPROTOCOL_ERR_BLACKLIST;

    sprotocol_frame_t f;
    memset(&f, 0, sizeof(f));
    f.header      = SPROTOCOL_FRAME_HEADER;
    f.version     = SPROTOCOL_FRAME_VERSION;
    f.src_addr    = h->config.local_addr;
    f.dest_addr   = dest_addr;
    f.seq         = h->local_seq++;
    f.domain_id   = domain_id;
    f.msg_type    = msg_type;
    f.payload_len = (uint8_t)len;
    if (len > 0 && payload) {
        memcpy(f.payload, payload, len);
    }

    return send_frame(h, &f);
}

int sprotocol_broadcast(sprotocol_handle_t handle, uint16_t domain_id,
                        uint8_t msg_type, const uint8_t *payload, size_t len) {
    struct sprotocol_handle *h = (struct sprotocol_handle*)handle;
    if (!h) return SPROTOCOL_ERR_INVALID_ARG;
    if (len > SPROTOCOL_MAX_PAYLOAD_LEN) return SPROTOCOL_ERR_INVALID_ARG;

    sprotocol_frame_t f;
    memset(&f, 0, sizeof(f));
    f.header       = SPROTOCOL_FRAME_HEADER;
    f.version      = SPROTOCOL_FRAME_VERSION;
    f.flags.broadcast = 1;
    f.src_addr     = h->config.local_addr;
    f.dest_addr    = SPROTOCOL_ADDR_BROADCAST;
    f.seq          = h->local_seq++;
    f.domain_id    = domain_id;
    f.msg_type     = msg_type;
    f.payload_len  = (uint8_t)len;
    if (len > 0 && payload) {
        memcpy(f.payload, payload, len);
    }

    return send_frame(h, &f);
}

/* =========================================================================
 * 心跳
 * ========================================================================= */

int sprotocol_send_heartbeat(sprotocol_handle_t handle) {
    struct sprotocol_handle *h = (struct sprotocol_handle*)handle;
    if (!h) return SPROTOCOL_ERR_INVALID_ARG;

    /* 从机向主机发心跳 */
    uint8_t dest = (h->config.role == SPROTOCOL_ROLE_SLAVE)
                   ? SPROTOCOL_ADDR_MASTER
                   : SPROTOCOL_ADDR_BROADCAST;

    sprotocol_frame_t f;
    memset(&f, 0, sizeof(f));
    f.header      = SPROTOCOL_FRAME_HEADER;
    f.version     = SPROTOCOL_FRAME_VERSION;
    f.src_addr    = h->config.local_addr;
    f.dest_addr   = dest;
    f.seq         = h->local_seq++;
    f.domain_id   = SPROTOCOL_DOMAIN_BASE;
    f.msg_type    = SPROTOCOL_MSG_HEARTBEAT;
    f.payload_len = 0;

    return send_frame(h, &f);
}

int sprotocol_is_device_online(sprotocol_handle_t handle, uint8_t addr) {
    struct sprotocol_handle *h = (struct sprotocol_handle*)handle;
    if (!h) return 0;

    int idx = find_slave_idx(h, addr);
    if (idx < 0) return 0;
    return h->slaves[idx].online == SPROTOCOL_DEVICE_ONLINE ? 1 : 0;
}

/* =========================================================================
 * 序列号
 * ========================================================================= */

uint16_t sprotocol_get_tx_seq(sprotocol_handle_t handle, uint8_t addr) {
    struct sprotocol_handle *h = (struct sprotocol_handle*)handle;
    if (!h) return 0;

    if (addr == h->config.local_addr) {
        return h->local_seq;
    }
    int idx = find_slave_idx(h, addr);
    if (idx < 0) return 0;
    return h->slaves[idx].seq_tx;
}

void sprotocol_set_seq_save_interval(sprotocol_handle_t handle, uint16_t interval_ms) {
    struct sprotocol_handle *h = (struct sprotocol_handle*)handle;
    if (!h) return;
    h->config.seq_save_interval = interval_ms;
}

/* =========================================================================
 * 黑名单
 * ========================================================================= */

int sprotocol_is_blacklisted(sprotocol_handle_t handle, uint8_t addr) {
    struct sprotocol_handle *h = (struct sprotocol_handle*)handle;
    if (!h) return 0;
    return blacklist_check(h, addr);
}

int sprotocol_get_blacklist_count(sprotocol_handle_t handle) {
    struct sprotocol_handle *h = (struct sprotocol_handle*)handle;
    if (!h) return 0;
    return h->blacklist_count;
}
