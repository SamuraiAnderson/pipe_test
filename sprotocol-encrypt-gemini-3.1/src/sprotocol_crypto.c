#include "sprotocol_crypto.h"
#include <string.h>

int sprotocol_crypto_init(sprotocol_crypto_t* crypto) {
    if (!crypto) return SPROTOCOL_ERR_INVALID_ARG;
    
    memset(crypto, 0, sizeof(sprotocol_crypto_t));
    
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        return SPROTOCOL_ERR_CRYPTO;
    }
    
    crypto->initialized = true;
    return SPROTOCOL_OK;
}

void sprotocol_crypto_deinit(sprotocol_crypto_t* crypto) {
    if (!crypto || !crypto->initialized) return;
    
    if (crypto->key_id != 0) {
        psa_destroy_key(crypto->key_id);
        crypto->key_id = 0;
    }
    
    crypto->initialized = false;
}

int sprotocol_crypto_generate_keys(sprotocol_crypto_t* crypto) {
    if (!crypto || !crypto->initialized) return SPROTOCOL_ERR_INVALID_ARG;
    
    if (crypto->key_id != 0) {
        psa_destroy_key(crypto->key_id);
        crypto->key_id = 0;
    }
    
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256);
    
    psa_status_t status = psa_generate_key(&attributes, &crypto->key_id);
    if (status != PSA_SUCCESS) return SPROTOCOL_ERR_CRYPTO;
    
    size_t exported_length = 0;
    status = psa_export_public_key(crypto->key_id, crypto->public_key, sizeof(crypto->public_key), &exported_length);
    if (status != PSA_SUCCESS || exported_length != SPROTOCOL_PUBKEY_LEN) {
        psa_destroy_key(crypto->key_id);
        crypto->key_id = 0;
        return SPROTOCOL_ERR_CRYPTO;
    }
    
    return SPROTOCOL_OK;
}

int sprotocol_crypto_compute_shared(sprotocol_crypto_t* crypto, const uint8_t* peer_pubkey, size_t pubkey_len) {
    if (!crypto || !crypto->initialized || !peer_pubkey || pubkey_len != SPROTOCOL_PUBKEY_LEN) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }
    
    if (crypto->key_id == 0) return SPROTOCOL_ERR_INVALID_STATE;
    
    size_t shared_secret_length = 0;
    psa_status_t status = psa_raw_key_agreement(PSA_ALG_ECDH, crypto->key_id,
                                                peer_pubkey, pubkey_len,
                                                crypto->shared_secret, sizeof(crypto->shared_secret),
                                                &shared_secret_length);
                                                
    if (status != PSA_SUCCESS || shared_secret_length != SPROTOCOL_SHARED_SECRET_LEN) {
        return SPROTOCOL_ERR_CRYPTO;
    }
    
    crypto->has_shared_secret = true;
    return SPROTOCOL_OK;
}

static void derive_aes_key_iv(const uint8_t* shared_secret, uint16_t seq, uint8_t* key, uint8_t* iv) {
    memcpy(key, shared_secret, 16);
    memcpy(iv, shared_secret + 16, 16);
    iv[14] ^= (seq >> 8) & 0xFF;
    iv[15] ^= seq & 0xFF;
}

int sprotocol_crypto_encrypt(const uint8_t* shared_secret, uint16_t seq, const uint8_t* input, size_t len, uint8_t* output) {
    if (!shared_secret || (!input && len > 0) || (!output && len > 0)) return SPROTOCOL_ERR_INVALID_ARG;
    if (len == 0) return SPROTOCOL_OK;
    
    uint8_t key[16];
    uint8_t iv[16];
    derive_aes_key_iv(shared_secret, seq, key, iv);
    
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_CTR);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 128);
    
    mbedtls_svc_key_id_t key_id;
    psa_status_t status = psa_import_key(&attributes, key, sizeof(key), &key_id);
    if (status != PSA_SUCCESS) return SPROTOCOL_ERR_CRYPTO;
    
    psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;
    status = psa_cipher_encrypt_setup(&operation, key_id, PSA_ALG_CTR);
    if (status != PSA_SUCCESS) {
        psa_destroy_key(key_id);
        return SPROTOCOL_ERR_CRYPTO;
    }
    
    status = psa_cipher_set_iv(&operation, iv, sizeof(iv));
    if (status != PSA_SUCCESS) {
        psa_cipher_abort(&operation);
        psa_destroy_key(key_id);
        return SPROTOCOL_ERR_CRYPTO;
    }
    
    size_t out_len = 0;
    status = psa_cipher_update(&operation, input, len, output, len, &out_len);
    if (status != PSA_SUCCESS) {
        psa_cipher_abort(&operation);
        psa_destroy_key(key_id);
        return SPROTOCOL_ERR_CRYPTO;
    }
    
    size_t finish_len = 0;
    status = psa_cipher_finish(&operation, output + out_len, len - out_len, &finish_len);
    
    psa_destroy_key(key_id);
    
    return status == PSA_SUCCESS ? SPROTOCOL_OK : SPROTOCOL_ERR_CRYPTO;
}

int sprotocol_crypto_decrypt(const uint8_t* shared_secret, uint16_t seq, const uint8_t* input, size_t len, uint8_t* output) {
    if (!shared_secret || (!input && len > 0) || (!output && len > 0)) return SPROTOCOL_ERR_INVALID_ARG;
    if (len == 0) return SPROTOCOL_OK;
    
    uint8_t key[16];
    uint8_t iv[16];
    derive_aes_key_iv(shared_secret, seq, key, iv);
    
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_CTR);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 128);
    
    mbedtls_svc_key_id_t key_id;
    psa_status_t status = psa_import_key(&attributes, key, sizeof(key), &key_id);
    if (status != PSA_SUCCESS) return SPROTOCOL_ERR_CRYPTO;
    
    psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;
    status = psa_cipher_decrypt_setup(&operation, key_id, PSA_ALG_CTR);
    if (status != PSA_SUCCESS) {
        psa_destroy_key(key_id);
        return SPROTOCOL_ERR_CRYPTO;
    }
    
    status = psa_cipher_set_iv(&operation, iv, sizeof(iv));
    if (status != PSA_SUCCESS) {
        psa_cipher_abort(&operation);
        psa_destroy_key(key_id);
        return SPROTOCOL_ERR_CRYPTO;
    }
    
    size_t out_len = 0;
    status = psa_cipher_update(&operation, input, len, output, len, &out_len);
    if (status != PSA_SUCCESS) {
        psa_cipher_abort(&operation);
        psa_destroy_key(key_id);
        return SPROTOCOL_ERR_CRYPTO;
    }
    
    size_t finish_len = 0;
    status = psa_cipher_finish(&operation, output + out_len, len - out_len, &finish_len);
    
    psa_destroy_key(key_id);
    
    return status == PSA_SUCCESS ? SPROTOCOL_OK : SPROTOCOL_ERR_CRYPTO;
}
