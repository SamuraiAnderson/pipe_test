/**
 * @file crypto.c
 * @brief 加密模块 (简化实现)
 * 
 * 注：完整的ECC加密需要mbedTLS完整配置，这里提供框架实现。
 * 实际项目中需要链接mbedTLS库并配置适当的加密选项。
 */

#include "sprotocol.h"
#include "sprotocol_internal.h"
#include <string.h>
#include <stdlib.h>

/* 简化实现：使用mbedTLS的头文件（如果可用） */
#if defined(MBEDTLS_CONFIG_FILE)
#include MBEDTLS_CONFIG_FILE
#endif

/* 简单的加密上下文结构 */
typedef struct {
    uint8_t enabled;
    uint8_t type;
    uint8_t pubkey[64];
    uint8_t privkey[32];
    uint8_t shared_secret[32];
    uint8_t has_keypair;
    uint8_t has_shared_secret;
} crypto_context_t;

static crypto_context_t g_crypto_ctx;

int crypto_init(sprotocol_handle_t handle) {
    if (!handle) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }
    
    memset(&g_crypto_ctx, 0, sizeof(g_crypto_ctx));
    g_crypto_ctx.enabled = handle->config.encryption_enabled;
    g_crypto_ctx.type = handle->config.enc_type;
    
    if (g_crypto_ctx.enabled && g_crypto_ctx.type == SPROTOCOL_ENC_ECC) {
        /* 生成ECC密钥对（简化：生成随机数据作为示例） */
        /* 实际实现应调用mbedTLS的ecdh_gen_public */
        for (int i = 0; i < 32; i++) {
            g_crypto_ctx.privkey[i] = (uint8_t)(rand() & 0xFF);
        }
        g_crypto_ctx.has_keypair = 1;
    }
    
    return SPROTOCOL_OK;
}

void crypto_deinit(sprotocol_handle_t handle) {
    (void)handle;
    memset(&g_crypto_ctx, 0, sizeof(g_crypto_ctx));
}

int crypto_ecc_generate_keypair(sprotocol_handle_t handle, uint8_t* pubkey, size_t* pubkey_len) {
    (void)handle;
    
    if (!pubkey || !pubkey_len) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }
    
    if (!g_crypto_ctx.enabled || g_crypto_ctx.type != SPROTOCOL_ENC_ECC) {
        return SPROTOCOL_ERR_CRYPTO;
    }
    
    /* 简化实现：返回示例公钥 */
    /* 实际实现应调用mbedTLS的ecdh_gen_public */
    if (*pubkey_len < 64) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }
    
    memcpy(pubkey, g_crypto_ctx.pubkey, 64);
    *pubkey_len = 64;
    
    return SPROTOCOL_OK;
}

int crypto_ecc_compute_shared_secret(sprotocol_handle_t handle, const uint8_t* peer_pubkey,
                                      size_t peer_pubkey_len, uint8_t* shared_secret,
                                      size_t* secret_len) {
    (void)handle;
    (void)peer_pubkey_len;
    
    if (!peer_pubkey || !shared_secret || !secret_len) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }
    
    if (!g_crypto_ctx.enabled || g_crypto_ctx.type != SPROTOCOL_ENC_ECC) {
        return SPROTOCOL_ERR_CRYPTO;
    }
    
    /* 简化实现：生成示例共享密钥 */
    /* 实际实现应调用mbedTLS的ecdh_compute_shared */
    if (*secret_len < 32) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }
    
    for (int i = 0; i < 32; i++) {
        g_crypto_ctx.shared_secret[i] = (uint8_t)(rand() & 0xFF);
        shared_secret[i] = g_crypto_ctx.shared_secret[i];
    }
    g_crypto_ctx.has_shared_secret = 1;
    *secret_len = 32;
    
    return SPROTOCOL_OK;
}

int crypto_encrypt(sprotocol_handle_t handle, const uint8_t* plaintext, size_t plaintext_len,
                   uint8_t* ciphertext, size_t* ciphertext_len) {
    (void)handle;
    
    if (!plaintext || !ciphertext || !ciphertext_len) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }
    
    if (!g_crypto_ctx.enabled) {
        /* 不加密，直接复制 */
        if (*ciphertext_len < plaintext_len) {
            return SPROTOCOL_ERR_INVALID_ARG;
        }
        memcpy(ciphertext, plaintext, plaintext_len);
        *ciphertext_len = plaintext_len;
        return SPROTOCOL_OK;
    }
    
    /* 简化实现：直接复制（应使用AES-GCM或ChaCha20-Poly1305） */
    /* 实际实现应调用mbedTLS的加密函数 */
    if (*ciphertext_len < plaintext_len + 16) {  /* 预留认证标签空间 */
        return SPROTOCOL_ERR_INVALID_ARG;
    }
    
    memcpy(ciphertext, plaintext, plaintext_len);
    /* 添加模拟认证标签 */
    for (int i = 0; i < 16; i++) {
        ciphertext[plaintext_len + i] = (uint8_t)(i + 0xA0);
    }
    *ciphertext_len = plaintext_len + 16;
    
    return SPROTOCOL_OK;
}

int crypto_decrypt(sprotocol_handle_t handle, const uint8_t* ciphertext, size_t ciphertext_len,
                   uint8_t* plaintext, size_t* plaintext_len) {
    (void)handle;
    
    if (!ciphertext || !plaintext || !plaintext_len) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }
    
    if (!g_crypto_ctx.enabled) {
        /* 不解密，直接复制 */
        if (*plaintext_len < ciphertext_len) {
            return SPROTOCOL_ERR_INVALID_ARG;
        }
        memcpy(plaintext, ciphertext, ciphertext_len);
        *plaintext_len = ciphertext_len;
        return SPROTOCOL_OK;
    }
    
    /* 简化实现：直接复制（应验证认证标签） */
    /* 实际实现应调用mbedTLS的解密函数 */
    if (ciphertext_len < 16) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }
    
    size_t data_len = ciphertext_len - 16;
    if (*plaintext_len < data_len) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }
    
    memcpy(plaintext, ciphertext, data_len);
    *plaintext_len = data_len;
    
    return SPROTOCOL_OK;
}
