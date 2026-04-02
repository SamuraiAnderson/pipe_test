#ifndef SPROTOCOL_INTERNAL_H
#define SPROTOCOL_INTERNAL_H

#include "sprotocol.h"
#include <string.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SPROTOCOL_ECDH_PUBKEY_LEN   65
#define SPROTOCOL_SHARED_SECRET_LEN 32
#define SPROTOCOL_AES_KEY_LEN       16
#define SPROTOCOL_GCM_IV_LEN        12
#define SPROTOCOL_GCM_TAG_LEN       16

#define SPROTOCOL_FRAME_OVERHEAD    11

typedef struct {
    uint8_t shared_secret[SPROTOCOL_SHARED_SECRET_LEN];
    uint8_t aes_key[SPROTOCOL_AES_KEY_LEN];
    bool    key_established;
} sprotocol_device_crypto_t;

struct sprotocol_handle {
    sprotocol_config_t        config;
    sprotocol_device_t        devices[SPROTOCOL_MAX_SLAVES];
    uint8_t                   device_count;

    sprotocol_blacklist_entry_t blacklist[SPROTOCOL_MAX_BLACKLIST];
    uint8_t                   blacklist_count;

    uint16_t                  local_seq;

    /* Per-device crypto state, indexed same as devices[] */
    sprotocol_device_crypto_t device_crypto[SPROTOCOL_MAX_SLAVES];

    /* Local ECC keypair (PSA key id), 0 if not generated */
    uint32_t                  ecc_key_id;
    uint8_t                   ecc_pubkey[SPROTOCOL_ECDH_PUBKEY_LEN];
    size_t                    ecc_pubkey_len;
    bool                      crypto_initialized;

    uint32_t                  last_seq_save_time;
};

/*============================================================================
 * Internal frame functions (sprotocol_frame.c)
 *============================================================================*/

size_t sprotocol_frame_encode(const sprotocol_frame_t *frame, uint8_t *buf, size_t buf_size);
int    sprotocol_frame_decode(const uint8_t *buf, size_t len, sprotocol_frame_t *frame);

/*============================================================================
 * Internal crypto functions (sprotocol_crypto.c)
 *============================================================================*/

int  sprotocol_crypto_init(struct sprotocol_handle *h);
void sprotocol_crypto_deinit(struct sprotocol_handle *h);
int  sprotocol_crypto_get_pubkey(struct sprotocol_handle *h, uint8_t *pubkey, size_t *pubkey_len);
int  sprotocol_crypto_compute_shared(struct sprotocol_handle *h, int device_idx,
                                     const uint8_t *peer_pubkey, size_t peer_pubkey_len);
int  sprotocol_crypto_encrypt(struct sprotocol_handle *h, int device_idx,
                              uint16_t seq, uint8_t src_addr, uint8_t dest_addr,
                              const uint8_t *plaintext, size_t plain_len,
                              uint8_t *ciphertext, size_t ct_size, size_t *ct_len);
int  sprotocol_crypto_decrypt(struct sprotocol_handle *h, int device_idx,
                              uint16_t seq, uint8_t src_addr, uint8_t dest_addr,
                              const uint8_t *ciphertext, size_t ct_len,
                              uint8_t *plaintext, size_t pt_size, size_t *pt_len);

/*============================================================================
 * Internal pairing functions (sprotocol_pair.c)
 *============================================================================*/

void sprotocol_pair_handle_input(struct sprotocol_handle *h, const sprotocol_frame_t *frame);
void sprotocol_pair_poll(struct sprotocol_handle *h, uint32_t now);

/*============================================================================
 * Internal helpers
 *============================================================================*/

static inline int sprotocol_find_device(struct sprotocol_handle *h, uint8_t addr)
{
    for (int i = 0; i < h->device_count; i++) {
        if (h->devices[i].addr == addr)
            return i;
    }
    return -1;
}

static inline int sprotocol_add_device(struct sprotocol_handle *h, uint8_t addr)
{
    if (h->device_count >= h->config.max_slaves)
        return -1;
    int idx = h->device_count;
    memset(&h->devices[idx], 0, sizeof(sprotocol_device_t));
    memset(&h->device_crypto[idx], 0, sizeof(sprotocol_device_crypto_t));
    h->devices[idx].addr = addr;
    h->device_count++;
    return idx;
}

static inline bool sprotocol_is_valid_slave_addr(uint8_t addr)
{
    return addr >= SPROTOCOL_MIN_SLAVE_ADDR && addr <= SPROTOCOL_MAX_SLAVE_ADDR;
}

static inline void sprotocol_send_frame(struct sprotocol_handle *h, sprotocol_frame_t *frame)
{
    uint8_t buf[SPROTOCOL_FRAME_OVERHEAD + SPROTOCOL_MAX_PAYLOAD_LEN + SPROTOCOL_GCM_TAG_LEN + 2];
    size_t len = sprotocol_frame_encode(frame, buf, sizeof(buf));
    if (len > 0 && h->config.send_cb) {
        h->config.send_cb(buf, len, h->config.user_data);
    }
}

#ifdef __cplusplus
}
#endif

#endif /* SPROTOCOL_INTERNAL_H */
