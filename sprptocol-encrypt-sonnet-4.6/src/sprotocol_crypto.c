#include "sprotocol_crypto.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* PSA Crypto API (mbedTLS 4.x) */
#include "psa/crypto.h"

/* -----------------------------------------------------------------------
 * 内部上下文
 * ----------------------------------------------------------------------- */
struct scrypto_ctx {
    mbedtls_svc_key_id_t keypair_id;   /* 本地 ECC 密钥对句柄 */
    int initialized;
};

static void log_psa_err(const char *func, psa_status_t st) {
    fprintf(stderr, "[crypto] %s failed: PSA status %d\n", func, (int)st);
}

scrypto_ctx_t* scrypto_init(void) {
    /* 初始化 PSA Crypto 子系统 */
    psa_status_t st = psa_crypto_init();
    if (st != PSA_SUCCESS) {
        log_psa_err("psa_crypto_init", st);
        return NULL;
    }

    scrypto_ctx_t *ctx = (scrypto_ctx_t*)calloc(1, sizeof(scrypto_ctx_t));
    if (!ctx) return NULL;

    /* 生成 secp256r1 ECC 密钥对，用于 ECDH */
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr,
        PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDH);

    st = psa_generate_key(&attr, &ctx->keypair_id);
    psa_reset_key_attributes(&attr);

    if (st != PSA_SUCCESS) {
        log_psa_err("psa_generate_key", st);
        free(ctx);
        return NULL;
    }

    ctx->initialized = 1;
    return ctx;
}

void scrypto_free(scrypto_ctx_t *ctx) {
    if (!ctx) return;
    if (ctx->initialized) {
        psa_destroy_key(ctx->keypair_id);
    }
    free(ctx);
}

int scrypto_get_pubkey(scrypto_ctx_t *ctx, uint8_t *buf, size_t buf_len, size_t *out_len) {
    if (!ctx || !buf || buf_len < SCRYPTO_PUBKEY_LEN) return -1;

    size_t olen = 0;
    /* psa_export_public_key 导出 uncompressed point (04 || x || y) */
    psa_status_t st = psa_export_public_key(ctx->keypair_id, buf, buf_len, &olen);
    if (st != PSA_SUCCESS) {
        log_psa_err("psa_export_public_key", st);
        return -1;
    }
    if (out_len) *out_len = olen;
    return 0;
}

int scrypto_derive_shared_key(scrypto_ctx_t *ctx,
                               const uint8_t *peer_pubkey, size_t peer_pubkey_len,
                               uint8_t out_key[SCRYPTO_KEY_LEN]) {
    if (!ctx || !peer_pubkey || !out_key) return -1;

    /* 用 psa_raw_key_agreement 做 ECDH，输出共享秘密（x 坐标，32 字节） */
    uint8_t shared_raw[32];
    size_t  shared_len = 0;

    psa_status_t st = psa_raw_key_agreement(
        PSA_ALG_ECDH,
        ctx->keypair_id,
        peer_pubkey, peer_pubkey_len,
        shared_raw, sizeof(shared_raw),
        &shared_len);

    if (st != PSA_SUCCESS) {
        log_psa_err("psa_raw_key_agreement", st);
        return -1;
    }

    /* 取前 SCRYPTO_KEY_LEN 字节作为 AES-128 密钥 */
    if (shared_len >= SCRYPTO_KEY_LEN) {
        memcpy(out_key, shared_raw, SCRYPTO_KEY_LEN);
    } else {
        memset(out_key, 0, SCRYPTO_KEY_LEN);
        memcpy(out_key, shared_raw, shared_len);
    }

    /* 清零敏感数据 */
    memset(shared_raw, 0, sizeof(shared_raw));
    return 0;
}

/* -----------------------------------------------------------------------
 * AES-128-CTR 加密/解密（PSA cipher API，one-shot）
 * PSA 的 CTR 模式：前 16 字节输入为 IV，后续为密文/明文
 * ----------------------------------------------------------------------- */
static int aes_ctr_crypt_psa(const uint8_t key[SCRYPTO_KEY_LEN],
                               const uint8_t iv[SCRYPTO_IV_LEN],
                               const uint8_t *in, size_t in_len,
                               uint8_t *out,
                               int encrypt) {
    psa_status_t st;

    /* 导入对称密钥 */
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, SCRYPTO_KEY_LEN * 8);
    psa_set_key_usage_flags(&attr,
        PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_CTR);

    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    st = psa_import_key(&attr, key, SCRYPTO_KEY_LEN, &key_id);
    psa_reset_key_attributes(&attr);
    if (st != PSA_SUCCESS) {
        log_psa_err("psa_import_key(AES)", st);
        return -1;
    }

    /* PSA one-shot cipher: input = IV || plaintext, output = ciphertext
     * psa_cipher_encrypt 接口：自动生成/附加 IV；
     * 我们需要指定 IV，使用 multi-part API */
    psa_cipher_operation_t op = PSA_CIPHER_OPERATION_INIT;

    if (encrypt) {
        st = psa_cipher_encrypt_setup(&op, key_id, PSA_ALG_CTR);
    } else {
        st = psa_cipher_decrypt_setup(&op, key_id, PSA_ALG_CTR);
    }
    if (st != PSA_SUCCESS) {
        log_psa_err("psa_cipher_*_setup", st);
        psa_destroy_key(key_id);
        return -1;
    }

    st = psa_cipher_set_iv(&op, iv, SCRYPTO_IV_LEN);
    if (st != PSA_SUCCESS) {
        log_psa_err("psa_cipher_set_iv", st);
        psa_cipher_abort(&op);
        psa_destroy_key(key_id);
        return -1;
    }

    size_t out_written = 0;
    size_t finish_written = 0;

    st = psa_cipher_update(&op, in, in_len, out, in_len + 16, &out_written);
    if (st != PSA_SUCCESS) {
        log_psa_err("psa_cipher_update", st);
        psa_cipher_abort(&op);
        psa_destroy_key(key_id);
        return -1;
    }

    st = psa_cipher_finish(&op, out + out_written, 16, &finish_written);
    psa_destroy_key(key_id);
    if (st != PSA_SUCCESS) {
        log_psa_err("psa_cipher_finish", st);
        return -1;
    }

    (void)finish_written;
    return 0;
}

int scrypto_aes_ctr_encrypt(const uint8_t key[SCRYPTO_KEY_LEN],
                             uint8_t iv[SCRYPTO_IV_LEN],
                             const uint8_t *in, size_t in_len,
                             uint8_t *out) {
    return aes_ctr_crypt_psa(key, iv, in, in_len, out, 1);
}

int scrypto_aes_ctr_decrypt(const uint8_t key[SCRYPTO_KEY_LEN],
                             uint8_t iv[SCRYPTO_IV_LEN],
                             const uint8_t *in, size_t in_len,
                             uint8_t *out) {
    return aes_ctr_crypt_psa(key, iv, in, in_len, out, 0);
}
