#ifndef SPROTOCOL_INTERNAL_H
#define SPROTOCOL_INTERNAL_H

#include "sprotocol.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <psa/crypto.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SPROTOCOL_INTERNAL_MAX_DEVICES (SPROTOCOL_MAX_SLAVES + 1U)
#define SPROTOCOL_WIRE_HEADER_LEN 11U
#define SPROTOCOL_WIRE_CRC_LEN 2U
#define SPROTOCOL_WIRE_MAX_LEN (SPROTOCOL_WIRE_HEADER_LEN + SPROTOCOL_MAX_PAYLOAD_LEN + SPROTOCOL_WIRE_CRC_LEN)
#define SPROTOCOL_PAYLOAD_ENCODE_LIMIT UINT8_MAX
#define SPROTOCOL_ENC_NONCE_LEN 12U
#define SPROTOCOL_ENC_TAG_LEN 16U
#define SPROTOCOL_SESSION_KEY_LEN 16U
#define SPROTOCOL_ECDH_PUBLIC_KEY_MAX_LEN 100U
#define SPROTOCOL_PERSIST_MAGIC 0x53505254UL

typedef struct {
    bool in_use;
    bool waiting_pair_rsp;
    bool waiting_pair_cfm;
    uint32_t pending_since;
    uint32_t violation_window_start;
    uint8_t violation_count;
    bool has_session_key;
    uint8_t session_key[SPROTOCOL_SESSION_KEY_LEN];
    psa_key_id_t ecdh_private_key;
    bool ecdh_private_key_valid;
    sprotocol_device_t device;
} sprotocol_peer_slot_t;

typedef struct {
    uint32_t magic;
    uint8_t addr;
    uint8_t pair_status;
    uint16_t seq_tx;
    uint16_t seq_rx;
} sprotocol_persist_record_t;

struct sprotocol_handle {
    sprotocol_config_t config;
    sprotocol_peer_slot_t peers[SPROTOCOL_INTERNAL_MAX_DEVICES];
    sprotocol_blacklist_entry_t blacklist[SPROTOCOL_MAX_BLACKLIST];
    uint8_t blacklist_count;
    uint16_t broadcast_seq;
    uint32_t last_seq_save;
};

typedef struct {
    uint8_t data[SPROTOCOL_WIRE_MAX_LEN];
    size_t len;
} sprotocol_wire_frame_t;

uint32_t sprotocol_now_ms(sprotocol_handle_t handle);
bool sprotocol_is_slave_addr(uint8_t addr);
bool sprotocol_is_control_msg(uint8_t msg_type);
bool sprotocol_should_encrypt(sprotocol_handle_t handle, uint8_t dest_addr, uint8_t msg_type, bool broadcast);

sprotocol_peer_slot_t* sprotocol_find_peer(sprotocol_handle_t handle, uint8_t addr);
sprotocol_peer_slot_t* sprotocol_alloc_peer(sprotocol_handle_t handle, uint8_t addr);
void sprotocol_reset_peer(sprotocol_handle_t handle, sprotocol_peer_slot_t* peer);
void sprotocol_mark_online(sprotocol_handle_t handle, sprotocol_peer_slot_t* peer, bool online);
void sprotocol_mark_pair_state(sprotocol_handle_t handle, sprotocol_peer_slot_t* peer, uint8_t status);
void sprotocol_note_violation(sprotocol_handle_t handle, uint8_t addr);
void sprotocol_blacklist_cleanup(sprotocol_handle_t handle);
void sprotocol_save_state(sprotocol_handle_t handle);
void sprotocol_load_state(sprotocol_handle_t handle);

int sprotocol_build_frame(const sprotocol_frame_t* frame, sprotocol_wire_frame_t* wire);
int sprotocol_parse_frame(const uint8_t* data, size_t len, sprotocol_frame_t* frame);

int sprotocol_crypto_global_init(void);
void sprotocol_crypto_peer_reset(sprotocol_peer_slot_t* peer);
int sprotocol_crypto_prepare_initiator(sprotocol_peer_slot_t* peer, uint8_t* public_key, size_t* public_key_len);
int sprotocol_crypto_prepare_responder(sprotocol_peer_slot_t* peer,
                                       const uint8_t* remote_key,
                                       size_t remote_key_len,
                                       uint8_t* public_key,
                                       size_t* public_key_len);
int sprotocol_crypto_complete_initiator(sprotocol_peer_slot_t* peer,
                                        const uint8_t* remote_key,
                                        size_t remote_key_len);
int sprotocol_crypto_encrypt(sprotocol_peer_slot_t* peer,
                             const uint8_t* aad,
                             size_t aad_len,
                             const uint8_t* plaintext,
                             size_t plaintext_len,
                             uint8_t* output,
                             size_t* output_len);
int sprotocol_crypto_decrypt(sprotocol_peer_slot_t* peer,
                             const uint8_t* aad,
                             size_t aad_len,
                             const uint8_t* input,
                             size_t input_len,
                             uint8_t* plaintext,
                             size_t* plaintext_len);

int sprotocol_send_frame_internal(sprotocol_handle_t handle,
                                  uint8_t dest_addr,
                                  uint16_t domain_id,
                                  uint8_t msg_type,
                                  const uint8_t* payload,
                                  size_t len,
                                  bool broadcast,
                                  bool allow_unpaired);

int sprotocol_handle_pair_request_frame(sprotocol_handle_t handle, const sprotocol_frame_t* frame);
int sprotocol_handle_pair_response_frame(sprotocol_handle_t handle, const sprotocol_frame_t* frame);
int sprotocol_handle_pair_confirm_frame(sprotocol_handle_t handle, const sprotocol_frame_t* frame);

#ifdef __cplusplus
}
#endif

#endif
