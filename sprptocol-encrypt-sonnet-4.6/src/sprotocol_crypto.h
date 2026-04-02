#ifndef SPROTOCOL_CRYPTO_H
#define SPROTOCOL_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

/* ECC secp256r1 未压缩公钥长度 */
#define SCRYPTO_PUBKEY_LEN  65
/* AES-128 密钥长度 */
#define SCRYPTO_KEY_LEN     16
/* AES 块大小（CTR 模式 IV 长度） */
#define SCRYPTO_IV_LEN      16

/**
 * @brief ECC 上下文（不透明）
 */
typedef struct scrypto_ctx scrypto_ctx_t;

/**
 * @brief 初始化加密上下文，生成 ECDH 密钥对
 * @return 新分配的上下文，失败返回 NULL
 */
scrypto_ctx_t* scrypto_init(void);

/**
 * @brief 释放加密上下文
 */
void scrypto_free(scrypto_ctx_t *ctx);

/**
 * @brief 导出本地公钥（未压缩格式，65 字节）
 * @param ctx       加密上下文
 * @param buf       输出缓冲区
 * @param buf_len   缓冲区大小（需 >= SCRYPTO_PUBKEY_LEN）
 * @param out_len   实际写入长度
 * @return 0 成功，<0 失败
 */
int scrypto_get_pubkey(scrypto_ctx_t *ctx, uint8_t *buf, size_t buf_len, size_t *out_len);

/**
 * @brief 用对方公钥派生共享密钥（ECDH），取前 SCRYPTO_KEY_LEN 字节作 AES 密钥
 * @param ctx           加密上下文
 * @param peer_pubkey   对方公钥（65 字节）
 * @param peer_pubkey_len 对方公钥长度
 * @param out_key       输出 AES 密钥（SCRYPTO_KEY_LEN 字节）
 * @return 0 成功，<0 失败
 */
int scrypto_derive_shared_key(scrypto_ctx_t *ctx,
                               const uint8_t *peer_pubkey, size_t peer_pubkey_len,
                               uint8_t out_key[SCRYPTO_KEY_LEN]);

/**
 * @brief AES-128-CTR 加密
 * @param key       16 字节密钥
 * @param iv        16 字节 IV（输入/输出，加密后更新）
 * @param in        明文
 * @param in_len    明文长度
 * @param out       密文（可与 in 相同，原地加密）
 * @return 0 成功，<0 失败
 */
int scrypto_aes_ctr_encrypt(const uint8_t key[SCRYPTO_KEY_LEN],
                             uint8_t iv[SCRYPTO_IV_LEN],
                             const uint8_t *in, size_t in_len,
                             uint8_t *out);

/**
 * @brief AES-128-CTR 解密（与加密对称）
 */
int scrypto_aes_ctr_decrypt(const uint8_t key[SCRYPTO_KEY_LEN],
                             uint8_t iv[SCRYPTO_IV_LEN],
                             const uint8_t *in, size_t in_len,
                             uint8_t *out);

#endif /* SPROTOCOL_CRYPTO_H */
