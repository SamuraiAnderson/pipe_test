#include "sprotocol_internal.h"

static int sprotocol_encode_pair_payload(sprotocol_handle_t handle,
                                         const uint8_t* public_key,
                                         size_t public_key_len,
                                         uint8_t* out,
                                         size_t* out_len)
{
    if (handle == NULL || out == NULL || out_len == NULL) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }

    out[0] = handle->config.encryption_enabled ? 1U : 0U;
    if (handle->config.encryption_enabled) {
        if (public_key == NULL || public_key_len == 0U || public_key_len > UINT8_MAX) {
            return SPROTOCOL_ERR_CRYPTO;
        }
        out[1] = (uint8_t)public_key_len;
        memcpy(&out[2], public_key, public_key_len);
        *out_len = public_key_len + 2U;
    } else {
        *out_len = 1U;
    }

    return SPROTOCOL_OK;
}

static int sprotocol_decode_pair_payload(const sprotocol_frame_t* frame,
                                         bool* encrypted,
                                         const uint8_t** public_key,
                                         size_t* public_key_len)
{
    uint8_t key_len;

    if (frame == NULL || encrypted == NULL || public_key == NULL || public_key_len == NULL) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }

    if (frame->payload_len < 1U) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }

    *encrypted = frame->payload[0] != 0U;
    *public_key = NULL;
    *public_key_len = 0U;
    if (!*encrypted) {
        return SPROTOCOL_OK;
    }

    if (frame->payload_len < 2U) {
        return SPROTOCOL_ERR_CRYPTO;
    }

    key_len = frame->payload[1];
    if ((size_t)key_len + 2U != frame->payload_len) {
        return SPROTOCOL_ERR_CRYPTO;
    }

    *public_key = &frame->payload[2];
    *public_key_len = key_len;
    return SPROTOCOL_OK;
}

static uint8_t sprotocol_master_paired_count(sprotocol_handle_t handle)
{
    uint8_t count = 0;
    size_t i;

    for (i = 0; i < SPROTOCOL_INTERNAL_MAX_DEVICES; ++i) {
        if (handle->peers[i].in_use &&
            handle->peers[i].device.pair_status == SPROTOCOL_PAIR_COMPLETE &&
            sprotocol_is_slave_addr(handle->peers[i].device.addr)) {
            ++count;
        }
    }

    return count;
}

int sprotocol_pair_request(sprotocol_handle_t handle, uint8_t slave_addr)
{
    sprotocol_peer_slot_t* peer;
    uint8_t payload[SPROTOCOL_MAX_PAYLOAD_LEN];
    uint8_t public_key[SPROTOCOL_ECDH_PUBLIC_KEY_MAX_LEN];
    size_t public_key_len = 0;
    size_t payload_len = 0;
    int rc;

    if (handle == NULL || handle->config.role != SPROTOCOL_ROLE_MASTER) {
        return SPROTOCOL_ERR_INVALID_STATE;
    }

    if (!sprotocol_is_slave_addr(slave_addr)) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }

    if (sprotocol_is_blacklisted(handle, slave_addr)) {
        return SPROTOCOL_ERR_BLACKLIST;
    }

    peer = sprotocol_find_peer(handle, slave_addr);
    if (peer == NULL && sprotocol_master_paired_count(handle) >= handle->config.max_slaves) {
        return SPROTOCOL_ERR_FULL;
    }

    peer = sprotocol_alloc_peer(handle, slave_addr);
    if (peer == NULL) {
        return SPROTOCOL_ERR_FULL;
    }

    sprotocol_crypto_peer_reset(peer);
    peer->waiting_pair_rsp = true;
    peer->waiting_pair_cfm = false;
    peer->pending_since = sprotocol_now_ms(handle);
    peer->device.seq_tx = 0;
    peer->device.seq_rx = 0;
    peer->device.pair_time = peer->pending_since;
    sprotocol_mark_pair_state(handle, peer, SPROTOCOL_PAIR_PENDING);

    if (handle->config.encryption_enabled) {
        rc = sprotocol_crypto_prepare_initiator(peer, public_key, &public_key_len);
        if (rc != SPROTOCOL_OK) {
            sprotocol_reset_peer(handle, peer);
            return rc;
        }
    }

    rc = sprotocol_encode_pair_payload(handle, public_key, public_key_len, payload, &payload_len);
    if (rc != SPROTOCOL_OK) {
        sprotocol_reset_peer(handle, peer);
        return rc;
    }

    rc = sprotocol_send_frame_internal(handle,
                                       slave_addr,
                                       SPROTOCOL_DOMAIN_BASE,
                                       SPROTOCOL_MSG_PAIR_REQ,
                                       payload,
                                       payload_len,
                                       false,
                                       true);
    if (rc != SPROTOCOL_OK) {
        sprotocol_reset_peer(handle, peer);
    }

    return rc;
}

int sprotocol_handle_pair_request_frame(sprotocol_handle_t handle, const sprotocol_frame_t* frame)
{
    sprotocol_peer_slot_t* peer;
    uint8_t payload[SPROTOCOL_MAX_PAYLOAD_LEN];
    uint8_t public_key[SPROTOCOL_ECDH_PUBLIC_KEY_MAX_LEN];
    const uint8_t* remote_key = NULL;
    size_t remote_key_len = 0;
    size_t public_key_len = 0;
    size_t payload_len = 0;
    bool encrypted = false;
    int rc;

    if (handle == NULL || frame == NULL) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }

    if (handle->config.role != SPROTOCOL_ROLE_SLAVE || frame->src_addr != SPROTOCOL_ADDR_MASTER) {
        return SPROTOCOL_ERR_INVALID_STATE;
    }

    rc = sprotocol_decode_pair_payload(frame, &encrypted, &remote_key, &remote_key_len);
    if (rc != SPROTOCOL_OK) {
        return rc;
    }

    if ((handle->config.encryption_enabled != 0U) != encrypted) {
        return SPROTOCOL_ERR_CRYPTO;
    }

    peer = sprotocol_alloc_peer(handle, SPROTOCOL_ADDR_MASTER);
    if (peer == NULL) {
        return SPROTOCOL_ERR_FULL;
    }

    sprotocol_crypto_peer_reset(peer);
    peer->waiting_pair_rsp = false;
    peer->waiting_pair_cfm = true;
    peer->pending_since = sprotocol_now_ms(handle);
    peer->device.seq_rx = frame->seq;
    peer->device.seq_tx = 0;
    peer->device.pair_time = peer->pending_since;
    sprotocol_mark_pair_state(handle, peer, SPROTOCOL_PAIR_PENDING);

    if (encrypted) {
        rc = sprotocol_crypto_prepare_responder(peer,
                                                remote_key,
                                                remote_key_len,
                                                public_key,
                                                &public_key_len);
        if (rc != SPROTOCOL_OK) {
            sprotocol_reset_peer(handle, peer);
            return rc;
        }
    }

    rc = sprotocol_encode_pair_payload(handle, public_key, public_key_len, payload, &payload_len);
    if (rc != SPROTOCOL_OK) {
        sprotocol_reset_peer(handle, peer);
        return rc;
    }

    return sprotocol_send_frame_internal(handle,
                                         SPROTOCOL_ADDR_MASTER,
                                         SPROTOCOL_DOMAIN_BASE,
                                         SPROTOCOL_MSG_PAIR_RSP,
                                         payload,
                                         payload_len,
                                         false,
                                         true);
}

int sprotocol_handle_pair_response_frame(sprotocol_handle_t handle, const sprotocol_frame_t* frame)
{
    sprotocol_peer_slot_t* peer;
    const uint8_t* remote_key = NULL;
    size_t remote_key_len = 0;
    bool encrypted = false;
    uint8_t confirm = 1U;
    int rc;

    if (handle == NULL || frame == NULL || handle->config.role != SPROTOCOL_ROLE_MASTER) {
        return SPROTOCOL_ERR_INVALID_STATE;
    }

    peer = sprotocol_find_peer(handle, frame->src_addr);
    if (peer == NULL || !peer->waiting_pair_rsp) {
        return SPROTOCOL_ERR_INVALID_STATE;
    }

    rc = sprotocol_decode_pair_payload(frame, &encrypted, &remote_key, &remote_key_len);
    if (rc != SPROTOCOL_OK) {
        return rc;
    }

    if ((handle->config.encryption_enabled != 0U) != encrypted) {
        return SPROTOCOL_ERR_CRYPTO;
    }

    if (encrypted) {
        rc = sprotocol_crypto_complete_initiator(peer, remote_key, remote_key_len);
        if (rc != SPROTOCOL_OK) {
            sprotocol_reset_peer(handle, peer);
            return rc;
        }
    }

    peer->waiting_pair_rsp = false;
    peer->waiting_pair_cfm = false;
    peer->device.pair_time = sprotocol_now_ms(handle);
    sprotocol_mark_pair_state(handle, peer, SPROTOCOL_PAIR_COMPLETE);
    sprotocol_mark_online(handle, peer, true);

    rc = sprotocol_send_frame_internal(handle,
                                       frame->src_addr,
                                       SPROTOCOL_DOMAIN_BASE,
                                       SPROTOCOL_MSG_PAIR_CFM,
                                       &confirm,
                                       sizeof(confirm),
                                       false,
                                       true);
    if (rc != SPROTOCOL_OK) {
        sprotocol_reset_peer(handle, peer);
    }
    return rc;
}

int sprotocol_handle_pair_confirm_frame(sprotocol_handle_t handle, const sprotocol_frame_t* frame)
{
    sprotocol_peer_slot_t* peer;

    if (handle == NULL || frame == NULL || handle->config.role != SPROTOCOL_ROLE_SLAVE) {
        return SPROTOCOL_ERR_INVALID_STATE;
    }

    peer = sprotocol_find_peer(handle, SPROTOCOL_ADDR_MASTER);
    if (peer == NULL || !peer->waiting_pair_cfm) {
        return SPROTOCOL_ERR_INVALID_STATE;
    }

    if (frame->payload_len != 1U || frame->payload[0] != 1U) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }

    peer->waiting_pair_cfm = false;
    peer->device.pair_time = sprotocol_now_ms(handle);
    sprotocol_mark_pair_state(handle, peer, SPROTOCOL_PAIR_COMPLETE);
    sprotocol_mark_online(handle, peer, true);
    return SPROTOCOL_OK;
}

int sprotocol_remove_device(sprotocol_handle_t handle, uint8_t addr)
{
    sprotocol_peer_slot_t* peer;

    if (handle == NULL) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }

    peer = sprotocol_find_peer(handle, addr);
    if (peer == NULL) {
        return SPROTOCOL_ERR_NOT_FOUND;
    }

    sprotocol_reset_peer(handle, peer);
    return SPROTOCOL_OK;
}

void sprotocol_remove_all_devices(sprotocol_handle_t handle)
{
    size_t i;

    if (handle == NULL) {
        return;
    }

    for (i = 0; i < SPROTOCOL_INTERNAL_MAX_DEVICES; ++i) {
        if (handle->peers[i].in_use) {
            sprotocol_reset_peer(handle, &handle->peers[i]);
        }
    }
}
