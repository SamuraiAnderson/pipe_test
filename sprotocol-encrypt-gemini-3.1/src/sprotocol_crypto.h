#ifndef SPROTOCOL_CRYPTO_H
#define SPROTOCOL_CRYPTO_H

#include "sprotocol.h"
#include <psa/crypto.h>

#define SPROTOCOL_PUBKEY_LEN 65 // Uncompressed SECP256R1 public key
#define SPROTOCOL_SHARED_SECRET_LEN 32

typedef struct {
    mbedtls_svc_key_id_t key_id;
    uint8_t public_key[SPROTOCOL_PUBKEY_LEN];
    uint8_t shared_secret[SPROTOCOL_SHARED_SECRET_LEN];
    bool initialized;
    bool has_shared_secret;
} sprotocol_crypto_t;

int sprotocol_crypto_init(sprotocol_crypto_t* crypto);
void sprotocol_crypto_deinit(sprotocol_crypto_t* crypto);

int sprotocol_crypto_generate_keys(sprotocol_crypto_t* crypto);
int sprotocol_crypto_compute_shared(sprotocol_crypto_t* crypto, const uint8_t* peer_pubkey, size_t pubkey_len);

int sprotocol_crypto_encrypt(const uint8_t* shared_secret, uint16_t seq, const uint8_t* input, size_t len, uint8_t* output);
int sprotocol_crypto_decrypt(const uint8_t* shared_secret, uint16_t seq, const uint8_t* input, size_t len, uint8_t* output);

#endif
