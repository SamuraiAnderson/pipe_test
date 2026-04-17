/**
 * @file sprotocol_crypto.h
 * @brief 内部加密工具：ECDH(secp256r1) + HKDF + AES-128-CTR + HMAC-SHA256
 *
 * 仅供 sprotocol 内部使用，不导出到公开 API。
 */

#ifndef SPROTOCOL_CRYPTO_H
#define SPROTOCOL_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SPC_ECC_PUB_LEN     65   /**< secp256r1 未压缩公钥: 0x04 || X || Y */
#define SPC_SHARED_LEN      32   /**< ECDH 共享密钥长度 */
#define SPC_AES_KEY_LEN     16   /**< AES-128 */
#define SPC_MAC_KEY_LEN     16
#define SPC_NONCE_BASE_LEN  8
#define SPC_AES_BLOCK_LEN   16
#define SPC_HMAC_TAG_LEN    8    /**< 截断的 MAC 标签长度 */
#define SPC_FRAME_NONCE_LEN 12   /**< 数据帧中的 nonce 长度 */

typedef struct spc_keypair {
    uint32_t key_id;             /**< psa_key_id_t (使用 uint32_t 避免暴露 PSA 头) */
    uint8_t  pub[SPC_ECC_PUB_LEN];
    int      valid;
} spc_keypair_t;

typedef struct spc_session {
    uint8_t  aes_key[SPC_AES_KEY_LEN];
    uint8_t  mac_key[SPC_MAC_KEY_LEN];
    uint8_t  nonce_base[SPC_NONCE_BASE_LEN];
    uint32_t aes_key_id;
    uint32_t mac_key_id;
    uint8_t  peer_pub[SPC_ECC_PUB_LEN]; /**< 对端公钥缓存（用于 confirm 校验） */
    int      ready;
} spc_session_t;

/** 模块全局初始化（多次调用安全） */
int spc_global_init(void);

/** 生成 ECC 密钥对，输出未压缩公钥 */
int spc_keypair_generate(spc_keypair_t* kp);

/** 释放密钥对 */
void spc_keypair_free(spc_keypair_t* kp);

/**
 * 用本地私钥 + 对端公钥派生会话密钥（AES + MAC + nonce_base）。
 * salt 可为 NULL（长度 0）。info 用作 HKDF 的 info 字段。
 */
int spc_session_derive(spc_session_t* sess,
                       const spc_keypair_t* local,
                       const uint8_t* peer_pub, size_t peer_pub_len,
                       const uint8_t* info, size_t info_len);

/** 释放会话（销毁 PSA key_id） */
void spc_session_free(spc_session_t* sess);

/**
 * AES-128-CTR 加/解密（自反，相同操作）。
 * iv 长度 16（CTR 计数块），通常前 12 字节为 nonce、后 4 字节计数器=0。
 */
int spc_aes_ctr_xcrypt(const spc_session_t* sess,
                       const uint8_t iv[SPC_AES_BLOCK_LEN],
                       const uint8_t* in, uint8_t* out, size_t len);

/**
 * 基于 mac_key 的 HMAC-SHA256，输出 32 字节 tag。
 */
int spc_hmac_sha256(const spc_session_t* sess,
                    const uint8_t* msg, size_t msg_len,
                    uint8_t out_tag[32]);

/** 常量时间比较 */
int spc_consttime_memcmp(const uint8_t* a, const uint8_t* b, size_t n);

/** 安全随机字节 */
int spc_random_bytes(uint8_t* out, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* SPROTOCOL_CRYPTO_H */
