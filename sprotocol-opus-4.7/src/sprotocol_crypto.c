/**
 * @file sprotocol_crypto.c
 * @brief 基于 mbedTLS 4.x PSA Crypto API 的封装实现。
 */

#include "sprotocol_crypto.h"

#include <psa/crypto.h>

#include <pthread.h>
#include <string.h>

/* ------------------------------------------------------------------- */
/* 全局初始化                                                          */
/* ------------------------------------------------------------------- */

static pthread_once_t g_psa_once = PTHREAD_ONCE_INIT;
static psa_status_t   g_psa_init_status = PSA_ERROR_GENERIC_ERROR;

static void psa_init_once(void)
{
    g_psa_init_status = psa_crypto_init();
}

int spc_global_init(void)
{
    pthread_once(&g_psa_once, psa_init_once);
    return (g_psa_init_status == PSA_SUCCESS) ? 0 : -1;
}

/* ------------------------------------------------------------------- */
/* 工具                                                                */
/* ------------------------------------------------------------------- */

int spc_consttime_memcmp(const uint8_t* a, const uint8_t* b, size_t n)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < n; ++i) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0 ? 0 : 1;
}

int spc_random_bytes(uint8_t* out, size_t len)
{
    if (spc_global_init() != 0) return -1;
    return psa_generate_random(out, len) == PSA_SUCCESS ? 0 : -1;
}

/* ------------------------------------------------------------------- */
/* ECC 密钥对                                                          */
/* ------------------------------------------------------------------- */

int spc_keypair_generate(spc_keypair_t* kp)
{
    if (!kp) return -1;
    if (spc_global_init() != 0) return -1;

    memset(kp, 0, sizeof(*kp));

    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDH);

    psa_key_id_t kid = 0;
    psa_status_t s = psa_generate_key(&attr, &kid);
    psa_reset_key_attributes(&attr);
    if (s != PSA_SUCCESS) return -1;

    size_t pub_len = 0;
    s = psa_export_public_key(kid, kp->pub, sizeof(kp->pub), &pub_len);
    if (s != PSA_SUCCESS || pub_len != SPC_ECC_PUB_LEN) {
        psa_destroy_key(kid);
        return -1;
    }
    kp->key_id = (uint32_t)kid;
    kp->valid = 1;
    return 0;
}

void spc_keypair_free(spc_keypair_t* kp)
{
    if (!kp || !kp->valid) return;
    psa_destroy_key((psa_key_id_t)kp->key_id);
    memset(kp, 0, sizeof(*kp));
}

/* ------------------------------------------------------------------- */
/* 会话密钥派生：ECDH + HKDF-SHA256                                    */
/* ------------------------------------------------------------------- */

static int import_raw_key(const uint8_t* bytes, size_t len,
                          psa_key_type_t type, psa_algorithm_t alg,
                          psa_key_usage_t usage, psa_key_id_t* out_id)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, type);
    psa_set_key_bits(&attr, (size_t)(len * 8));
    psa_set_key_usage_flags(&attr, usage);
    psa_set_key_algorithm(&attr, alg);

    psa_status_t s = psa_import_key(&attr, bytes, len, out_id);
    psa_reset_key_attributes(&attr);
    return s == PSA_SUCCESS ? 0 : -1;
}

int spc_session_derive(spc_session_t* sess,
                       const spc_keypair_t* local,
                       const uint8_t* peer_pub, size_t peer_pub_len,
                       const uint8_t* info, size_t info_len)
{
    if (!sess || !local || !local->valid || !peer_pub) return -1;
    if (peer_pub_len != SPC_ECC_PUB_LEN) return -1;
    if (spc_global_init() != 0) return -1;

    memset(sess, 0, sizeof(*sess));

    /* 1. ECDH 共享密钥 */
    uint8_t shared[SPC_SHARED_LEN];
    size_t shared_len = 0;
    psa_status_t s = psa_raw_key_agreement(
        PSA_ALG_ECDH,
        (psa_key_id_t)local->key_id,
        peer_pub, peer_pub_len,
        shared, sizeof(shared), &shared_len);
    if (s != PSA_SUCCESS || shared_len == 0) return -1;

    /* 2. HKDF-SHA256 派生 16+16+8 = 40 字节 */
    uint8_t derived[SPC_AES_KEY_LEN + SPC_MAC_KEY_LEN + SPC_NONCE_BASE_LEN];
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    s = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (s != PSA_SUCCESS) goto fail_zero;

    /* salt 为空 */
    s = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT, NULL, 0);
    if (s != PSA_SUCCESS) goto fail_op;
    s = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                       shared, shared_len);
    if (s != PSA_SUCCESS) goto fail_op;
    if (info && info_len) {
        s = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO,
                                           info, info_len);
        if (s != PSA_SUCCESS) goto fail_op;
    } else {
        s = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO,
                                           (const uint8_t*)"sprotocol", 9);
        if (s != PSA_SUCCESS) goto fail_op;
    }
    s = psa_key_derivation_output_bytes(&op, derived, sizeof(derived));
    if (s != PSA_SUCCESS) goto fail_op;
    psa_key_derivation_abort(&op);

    memcpy(sess->aes_key,    derived,                                 SPC_AES_KEY_LEN);
    memcpy(sess->mac_key,    derived + SPC_AES_KEY_LEN,               SPC_MAC_KEY_LEN);
    memcpy(sess->nonce_base, derived + SPC_AES_KEY_LEN + SPC_MAC_KEY_LEN,
           SPC_NONCE_BASE_LEN);
    memcpy(sess->peer_pub, peer_pub, SPC_ECC_PUB_LEN);

    /* 3. 导入 PSA key 缓存 */
    if (import_raw_key(sess->aes_key, SPC_AES_KEY_LEN,
                       PSA_KEY_TYPE_AES, PSA_ALG_CTR,
                       PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT,
                       (psa_key_id_t*)&sess->aes_key_id) != 0) {
        goto fail_zero;
    }
    if (import_raw_key(sess->mac_key, SPC_MAC_KEY_LEN,
                       PSA_KEY_TYPE_HMAC, PSA_ALG_HMAC(PSA_ALG_SHA_256),
                       PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE,
                       (psa_key_id_t*)&sess->mac_key_id) != 0) {
        psa_destroy_key((psa_key_id_t)sess->aes_key_id);
        goto fail_zero;
    }

    sess->ready = 1;
    /* 清理临时数据 */
    memset(shared,  0, sizeof(shared));
    memset(derived, 0, sizeof(derived));
    return 0;

fail_op:
    psa_key_derivation_abort(&op);
fail_zero:
    memset(shared, 0, sizeof(shared));
    memset(sess, 0, sizeof(*sess));
    return -1;
}

void spc_session_free(spc_session_t* sess)
{
    if (!sess) return;
    if (sess->ready) {
        if (sess->aes_key_id) psa_destroy_key((psa_key_id_t)sess->aes_key_id);
        if (sess->mac_key_id) psa_destroy_key((psa_key_id_t)sess->mac_key_id);
    }
    memset(sess, 0, sizeof(*sess));
}

/* ------------------------------------------------------------------- */
/* AES-128-CTR                                                         */
/* ------------------------------------------------------------------- */

int spc_aes_ctr_xcrypt(const spc_session_t* sess,
                       const uint8_t iv[SPC_AES_BLOCK_LEN],
                       const uint8_t* in, uint8_t* out, size_t len)
{
    if (!sess || !sess->ready || !iv || (len > 0 && (!in || !out))) return -1;
    if (len == 0) return 0;

    psa_cipher_operation_t op = PSA_CIPHER_OPERATION_INIT;
    psa_status_t s = psa_cipher_encrypt_setup(&op,
        (psa_key_id_t)sess->aes_key_id, PSA_ALG_CTR);
    if (s != PSA_SUCCESS) return -1;

    s = psa_cipher_set_iv(&op, iv, SPC_AES_BLOCK_LEN);
    if (s != PSA_SUCCESS) goto fail;

    size_t out_len = 0;
    s = psa_cipher_update(&op, in, len, out, len, &out_len);
    if (s != PSA_SUCCESS) goto fail;

    size_t finish_len = 0;
    s = psa_cipher_finish(&op, out + out_len, len - out_len, &finish_len);
    if (s != PSA_SUCCESS) goto fail;

    return 0;

fail:
    psa_cipher_abort(&op);
    return -1;
}

/* ------------------------------------------------------------------- */
/* HMAC-SHA256                                                         */
/* ------------------------------------------------------------------- */

int spc_hmac_sha256(const spc_session_t* sess,
                    const uint8_t* msg, size_t msg_len,
                    uint8_t out_tag[32])
{
    if (!sess || !sess->ready || !out_tag) return -1;

    size_t mac_len = 0;
    psa_status_t s = psa_mac_compute(
        (psa_key_id_t)sess->mac_key_id,
        PSA_ALG_HMAC(PSA_ALG_SHA_256),
        msg, msg_len,
        out_tag, 32, &mac_len);
    if (s != PSA_SUCCESS || mac_len != 32) return -1;
    return 0;
}
