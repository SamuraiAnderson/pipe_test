#include "sprotocol_internal.h"

static int sprotocol_crypto_status_to_error(psa_status_t status)
{
    return status == PSA_SUCCESS ? SPROTOCOL_OK : SPROTOCOL_ERR_CRYPTO;
}

static int sprotocol_crypto_derive_session_key(sprotocol_peer_slot_t* peer,
                                               const uint8_t* shared_secret,
                                               size_t shared_secret_len)
{
    static const uint8_t salt[] = {
        's', 'p', 'r', 'o', 't', 'o', 'c', 'o', 'l'
    };
    static const uint8_t info[] = {
        'e', 'c', 'c', '-', 's', 'e', 's', 's', 'i', 'o', 'n'
    };
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_status_t status;
    int rc = SPROTOCOL_ERR_CRYPTO;

    status = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    status = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT, salt, sizeof(salt));
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    status = psa_key_derivation_input_bytes(&op,
                                            PSA_KEY_DERIVATION_INPUT_SECRET,
                                            shared_secret,
                                            shared_secret_len);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    status = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO, info, sizeof(info));
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    status = psa_key_derivation_output_bytes(&op, peer->session_key, sizeof(peer->session_key));
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    peer->has_session_key = true;
    rc = SPROTOCOL_OK;

cleanup:
    psa_key_derivation_abort(&op);
    return rc;
}

static int sprotocol_crypto_generate_keypair(sprotocol_peer_slot_t* peer, uint8_t* public_key, size_t* public_key_len)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t status;

    if (peer == NULL || public_key == NULL || public_key_len == NULL) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }

    if (peer->ecdh_private_key_valid) {
        psa_destroy_key(peer->ecdh_private_key);
        peer->ecdh_private_key_valid = false;
    }

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256);

    status = psa_generate_key(&attributes, &peer->ecdh_private_key);
    psa_reset_key_attributes(&attributes);
    if (status != PSA_SUCCESS) {
        return SPROTOCOL_ERR_CRYPTO;
    }

    peer->ecdh_private_key_valid = true;
    status = psa_export_public_key(peer->ecdh_private_key,
                                   public_key,
                                   SPROTOCOL_ECDH_PUBLIC_KEY_MAX_LEN,
                                   public_key_len);
    return sprotocol_crypto_status_to_error(status);
}

static int sprotocol_crypto_derive_shared_key(sprotocol_peer_slot_t* peer,
                                              const uint8_t* remote_key,
                                              size_t remote_key_len)
{
    uint8_t shared_secret[80];
    size_t shared_secret_len = 0;
    psa_status_t status;
    int rc;

    if (peer == NULL || remote_key == NULL || remote_key_len == 0U || !peer->ecdh_private_key_valid) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }

    status = psa_raw_key_agreement(PSA_ALG_ECDH,
                                   peer->ecdh_private_key,
                                   remote_key,
                                   remote_key_len,
                                   shared_secret,
                                   sizeof(shared_secret),
                                   &shared_secret_len);
    if (status != PSA_SUCCESS) {
        return SPROTOCOL_ERR_CRYPTO;
    }

    rc = sprotocol_crypto_derive_session_key(peer, shared_secret, shared_secret_len);
    memset(shared_secret, 0, sizeof(shared_secret));

    if (peer->ecdh_private_key_valid) {
        psa_destroy_key(peer->ecdh_private_key);
        peer->ecdh_private_key_valid = false;
        peer->ecdh_private_key = 0;
    }

    return rc;
}

static int sprotocol_crypto_import_aes_key(const uint8_t* key, psa_key_id_t* key_id)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t status;

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_GCM);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, SPROTOCOL_SESSION_KEY_LEN * 8U);

    status = psa_import_key(&attributes, key, SPROTOCOL_SESSION_KEY_LEN, key_id);
    psa_reset_key_attributes(&attributes);
    return sprotocol_crypto_status_to_error(status);
}

int sprotocol_crypto_global_init(void)
{
    return sprotocol_crypto_status_to_error(psa_crypto_init());
}

void sprotocol_crypto_peer_reset(sprotocol_peer_slot_t* peer)
{
    if (peer == NULL) {
        return;
    }

    if (peer->ecdh_private_key_valid) {
        psa_destroy_key(peer->ecdh_private_key);
    }

    peer->ecdh_private_key = 0;
    peer->ecdh_private_key_valid = false;
    peer->has_session_key = false;
    memset(peer->session_key, 0, sizeof(peer->session_key));
}

int sprotocol_crypto_prepare_initiator(sprotocol_peer_slot_t* peer, uint8_t* public_key, size_t* public_key_len)
{
    return sprotocol_crypto_generate_keypair(peer, public_key, public_key_len);
}

int sprotocol_crypto_prepare_responder(sprotocol_peer_slot_t* peer,
                                       const uint8_t* remote_key,
                                       size_t remote_key_len,
                                       uint8_t* public_key,
                                       size_t* public_key_len)
{
    int rc;

    rc = sprotocol_crypto_generate_keypair(peer, public_key, public_key_len);
    if (rc != SPROTOCOL_OK) {
        return rc;
    }

    return sprotocol_crypto_derive_shared_key(peer, remote_key, remote_key_len);
}

int sprotocol_crypto_complete_initiator(sprotocol_peer_slot_t* peer,
                                        const uint8_t* remote_key,
                                        size_t remote_key_len)
{
    return sprotocol_crypto_derive_shared_key(peer, remote_key, remote_key_len);
}

int sprotocol_crypto_encrypt(sprotocol_peer_slot_t* peer,
                             const uint8_t* aad,
                             size_t aad_len,
                             const uint8_t* plaintext,
                             size_t plaintext_len,
                             uint8_t* output,
                             size_t* output_len)
{
    psa_key_id_t key_id = 0;
    psa_status_t status;
    size_t cipher_len = 0;
    int rc;

    if (peer == NULL || output == NULL || output_len == NULL) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }

    if (!peer->has_session_key) {
        return SPROTOCOL_ERR_INVALID_STATE;
    }

    if (plaintext_len + 1U + SPROTOCOL_ENC_NONCE_LEN + SPROTOCOL_ENC_TAG_LEN > SPROTOCOL_PAYLOAD_ENCODE_LIMIT) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }

    rc = sprotocol_crypto_import_aes_key(peer->session_key, &key_id);
    if (rc != SPROTOCOL_OK) {
        return rc;
    }

    output[0] = SPROTOCOL_ENC_NONCE_LEN;
    status = psa_generate_random(&output[1], SPROTOCOL_ENC_NONCE_LEN);
    if (status != PSA_SUCCESS) {
        psa_destroy_key(key_id);
        return SPROTOCOL_ERR_CRYPTO;
    }

    status = psa_aead_encrypt(key_id,
                              PSA_ALG_GCM,
                              &output[1],
                              SPROTOCOL_ENC_NONCE_LEN,
                              aad,
                              aad_len,
                              plaintext,
                              plaintext_len,
                              &output[1U + SPROTOCOL_ENC_NONCE_LEN],
                              plaintext_len + SPROTOCOL_ENC_TAG_LEN,
                              &cipher_len);
    psa_destroy_key(key_id);
    if (status != PSA_SUCCESS) {
        return SPROTOCOL_ERR_CRYPTO;
    }

    *output_len = 1U + SPROTOCOL_ENC_NONCE_LEN + cipher_len;
    return SPROTOCOL_OK;
}

int sprotocol_crypto_decrypt(sprotocol_peer_slot_t* peer,
                             const uint8_t* aad,
                             size_t aad_len,
                             const uint8_t* input,
                             size_t input_len,
                             uint8_t* plaintext,
                             size_t* plaintext_len)
{
    psa_key_id_t key_id = 0;
    psa_status_t status;
    uint8_t nonce_len;
    int rc;

    if (peer == NULL || input == NULL || plaintext == NULL || plaintext_len == NULL) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }

    if (!peer->has_session_key || input_len < 1U + SPROTOCOL_ENC_TAG_LEN) {
        return SPROTOCOL_ERR_CRYPTO;
    }

    nonce_len = input[0];
    if (nonce_len != SPROTOCOL_ENC_NONCE_LEN || input_len <= 1U + nonce_len) {
        return SPROTOCOL_ERR_CRYPTO;
    }

    rc = sprotocol_crypto_import_aes_key(peer->session_key, &key_id);
    if (rc != SPROTOCOL_OK) {
        return rc;
    }

    status = psa_aead_decrypt(key_id,
                              PSA_ALG_GCM,
                              &input[1],
                              nonce_len,
                              aad,
                              aad_len,
                              &input[1U + nonce_len],
                              input_len - 1U - nonce_len,
                              plaintext,
                              SPROTOCOL_MAX_PAYLOAD_LEN,
                              plaintext_len);
    psa_destroy_key(key_id);
    return sprotocol_crypto_status_to_error(status);
}
