#include "sprotocol_internal.h"
#include "psa/crypto.h"

#define ECC_KEY_BITS 256

static bool psa_initialized = false;

int sprotocol_crypto_init(struct sprotocol_handle *h)
{
    if (!psa_initialized) {
        psa_status_t status = psa_crypto_init();
        if (status != PSA_SUCCESS)
            return SPROTOCOL_ERR_CRYPTO;
        psa_initialized = true;
    }

    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, ECC_KEY_BITS);

    mbedtls_svc_key_id_t key_id;
    psa_status_t status = psa_generate_key(&attr, &key_id);
    if (status != PSA_SUCCESS)
        return SPROTOCOL_ERR_CRYPTO;

    h->ecc_key_id = MBEDTLS_SVC_KEY_ID_GET_KEY_ID(key_id);

    status = psa_export_public_key(key_id,
                                   h->ecc_pubkey, sizeof(h->ecc_pubkey),
                                   &h->ecc_pubkey_len);
    if (status != PSA_SUCCESS) {
        psa_destroy_key(key_id);
        h->ecc_key_id = 0;
        return SPROTOCOL_ERR_CRYPTO;
    }

    h->crypto_initialized = true;
    return SPROTOCOL_OK;
}

void sprotocol_crypto_deinit(struct sprotocol_handle *h)
{
    if (h->ecc_key_id != 0) {
        mbedtls_svc_key_id_t key_id = mbedtls_svc_key_id_make(0, h->ecc_key_id);
        psa_destroy_key(key_id);
        h->ecc_key_id = 0;
    }
    h->crypto_initialized = false;
}

int sprotocol_crypto_get_pubkey(struct sprotocol_handle *h, uint8_t *pubkey, size_t *pubkey_len)
{
    if (!h->crypto_initialized)
        return SPROTOCOL_ERR_CRYPTO;
    if (h->ecc_pubkey_len > *pubkey_len)
        return SPROTOCOL_ERR_INVALID_ARG;
    memcpy(pubkey, h->ecc_pubkey, h->ecc_pubkey_len);
    *pubkey_len = h->ecc_pubkey_len;
    return SPROTOCOL_OK;
}

int sprotocol_crypto_compute_shared(struct sprotocol_handle *h, int device_idx,
                                    const uint8_t *peer_pubkey, size_t peer_pubkey_len)
{
    if (!h->crypto_initialized || device_idx < 0 || device_idx >= h->device_count)
        return SPROTOCOL_ERR_CRYPTO;

    mbedtls_svc_key_id_t key_id = mbedtls_svc_key_id_make(0, h->ecc_key_id);

    uint8_t shared[SPROTOCOL_SHARED_SECRET_LEN];
    size_t shared_len = 0;

    psa_status_t status = psa_raw_key_agreement(
        PSA_ALG_ECDH,
        key_id,
        peer_pubkey, peer_pubkey_len,
        shared, sizeof(shared),
        &shared_len);

    if (status != PSA_SUCCESS)
        return SPROTOCOL_ERR_CRYPTO;

    sprotocol_device_crypto_t *dc = &h->device_crypto[device_idx];
    memcpy(dc->shared_secret, shared, SPROTOCOL_SHARED_SECRET_LEN);
    memcpy(dc->aes_key, shared, SPROTOCOL_AES_KEY_LEN);
    dc->key_established = true;

    return SPROTOCOL_OK;
}

static void build_iv(uint16_t seq, uint8_t src_addr, uint8_t dest_addr,
                     uint8_t *iv)
{
    memset(iv, 0, SPROTOCOL_GCM_IV_LEN);
    iv[0] = (uint8_t)(seq & 0xFF);
    iv[1] = (uint8_t)(seq >> 8);
    iv[2] = src_addr;
    iv[3] = dest_addr;
    /* bytes 4-11 remain zero, providing uniqueness via seq */
}

int sprotocol_crypto_encrypt(struct sprotocol_handle *h, int device_idx,
                             uint16_t seq, uint8_t src_addr, uint8_t dest_addr,
                             const uint8_t *plaintext, size_t plain_len,
                             uint8_t *ciphertext, size_t ct_size, size_t *ct_len)
{
    if (device_idx < 0 || device_idx >= h->device_count)
        return SPROTOCOL_ERR_CRYPTO;

    sprotocol_device_crypto_t *dc = &h->device_crypto[device_idx];
    if (!dc->key_established)
        return SPROTOCOL_ERR_CRYPTO;

    /* Import AES key as a volatile PSA key for AEAD */
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_GCM);
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, SPROTOCOL_AES_KEY_LEN * 8);

    mbedtls_svc_key_id_t aes_key_id;
    psa_status_t status = psa_import_key(&attr, dc->aes_key, SPROTOCOL_AES_KEY_LEN, &aes_key_id);
    if (status != PSA_SUCCESS)
        return SPROTOCOL_ERR_CRYPTO;

    uint8_t iv[SPROTOCOL_GCM_IV_LEN];
    build_iv(seq, src_addr, dest_addr, iv);

    status = psa_aead_encrypt(aes_key_id, PSA_ALG_GCM,
                              iv, SPROTOCOL_GCM_IV_LEN,
                              NULL, 0,
                              plaintext, plain_len,
                              ciphertext, ct_size, ct_len);

    psa_destroy_key(aes_key_id);
    return (status == PSA_SUCCESS) ? SPROTOCOL_OK : SPROTOCOL_ERR_CRYPTO;
}

int sprotocol_crypto_decrypt(struct sprotocol_handle *h, int device_idx,
                             uint16_t seq, uint8_t src_addr, uint8_t dest_addr,
                             const uint8_t *ciphertext, size_t ct_len,
                             uint8_t *plaintext, size_t pt_size, size_t *pt_len)
{
    if (device_idx < 0 || device_idx >= h->device_count)
        return SPROTOCOL_ERR_CRYPTO;

    sprotocol_device_crypto_t *dc = &h->device_crypto[device_idx];
    if (!dc->key_established)
        return SPROTOCOL_ERR_CRYPTO;

    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_GCM);
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, SPROTOCOL_AES_KEY_LEN * 8);

    mbedtls_svc_key_id_t aes_key_id;
    psa_status_t status = psa_import_key(&attr, dc->aes_key, SPROTOCOL_AES_KEY_LEN, &aes_key_id);
    if (status != PSA_SUCCESS)
        return SPROTOCOL_ERR_CRYPTO;

    uint8_t iv[SPROTOCOL_GCM_IV_LEN];
    build_iv(seq, src_addr, dest_addr, iv);

    status = psa_aead_decrypt(aes_key_id, PSA_ALG_GCM,
                              iv, SPROTOCOL_GCM_IV_LEN,
                              NULL, 0,
                              ciphertext, ct_len,
                              plaintext, pt_size, pt_len);

    psa_destroy_key(aes_key_id);
    return (status == PSA_SUCCESS) ? SPROTOCOL_OK : SPROTOCOL_ERR_CRYPTO;
}
