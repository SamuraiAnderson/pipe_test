#include "sprotocol_internal.h"

#include <stdlib.h>

static uint8_t sprotocol_pack_aad_flags(const sprotocol_flags_t* flags)
{
    uint8_t value = 0;

    value |= (flags->broadcast ? 1U : 0U) << 0;
    value |= (flags->need_ack ? 1U : 0U) << 1;
    value |= (flags->encrypted ? 1U : 0U) << 2;
    value |= (flags->retransmit ? 1U : 0U) << 3;
    value |= (flags->fragmented ? 1U : 0U) << 4;
    return value;
}

static void sprotocol_fill_aad(const sprotocol_frame_t* frame, uint8_t aad[10])
{
    aad[0] = frame->header;
    aad[1] = frame->version;
    aad[2] = sprotocol_pack_aad_flags(&frame->flags);
    aad[3] = frame->src_addr;
    aad[4] = frame->dest_addr;
    aad[5] = (uint8_t)(frame->seq >> 8);
    aad[6] = (uint8_t)(frame->seq & 0xFFU);
    aad[7] = (uint8_t)(frame->domain_id >> 8);
    aad[8] = (uint8_t)(frame->domain_id & 0xFFU);
    aad[9] = frame->msg_type;
}

static bool sprotocol_addr_allowed_for_role(sprotocol_handle_t handle, uint8_t addr)
{
    if (addr == SPROTOCOL_ADDR_BROADCAST) {
        return true;
    }

    if (handle->config.role == SPROTOCOL_ROLE_MASTER) {
        return sprotocol_is_slave_addr(addr);
    }

    return addr == SPROTOCOL_ADDR_MASTER;
}

static int sprotocol_validate_rx_sequence(sprotocol_peer_slot_t* peer, const sprotocol_frame_t* frame)
{
    if (peer == NULL || frame == NULL) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }

    if (frame->flags.broadcast) {
        return SPROTOCOL_OK;
    }

    if (frame->seq == 0U) {
        return SPROTOCOL_ERR_SEQ;
    }

    if (peer->device.seq_rx != 0U && frame->seq <= peer->device.seq_rx) {
        return SPROTOCOL_ERR_SEQ;
    }

    peer->device.seq_rx = frame->seq;
    return SPROTOCOL_OK;
}

static int sprotocol_next_tx_sequence(sprotocol_handle_t handle, uint8_t dest_addr, bool broadcast, uint16_t* seq)
{
    sprotocol_peer_slot_t* peer;

    if (handle == NULL || seq == NULL) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }

    if (broadcast) {
        handle->broadcast_seq = (uint16_t)(handle->broadcast_seq + 1U);
        if (handle->broadcast_seq == 0U) {
            handle->broadcast_seq = 1U;
        }
        *seq = handle->broadcast_seq;
        return SPROTOCOL_OK;
    }

    peer = sprotocol_find_peer(handle, dest_addr);
    if (peer == NULL) {
        peer = sprotocol_alloc_peer(handle, dest_addr);
    }
    if (peer == NULL) {
        return SPROTOCOL_ERR_FULL;
    }

    peer->device.seq_tx = (uint16_t)(peer->device.seq_tx + 1U);
    if (peer->device.seq_tx == 0U) {
        peer->device.seq_tx = 1U;
    }
    *seq = peer->device.seq_tx;
    return SPROTOCOL_OK;
}

static int sprotocol_dispatch_recv_callback(sprotocol_handle_t handle,
                                            const sprotocol_frame_t* frame,
                                            const uint8_t* payload,
                                            size_t payload_len)
{
    if (handle->config.recv_cb == NULL) {
        return SPROTOCOL_OK;
    }

    handle->config.recv_cb(frame->src_addr,
                           frame->domain_id,
                           frame->msg_type,
                           payload,
                           payload_len,
                           handle->config.user_data);
    return SPROTOCOL_OK;
}

uint32_t sprotocol_now_ms(sprotocol_handle_t handle)
{
    if (handle == NULL || handle->config.get_time == NULL) {
        return 0U;
    }

    return handle->config.get_time();
}

bool sprotocol_is_slave_addr(uint8_t addr)
{
    return addr >= SPROTOCOL_MIN_SLAVE_ADDR && addr <= SPROTOCOL_MAX_SLAVE_ADDR;
}

bool sprotocol_is_control_msg(uint8_t msg_type)
{
    return msg_type == SPROTOCOL_MSG_PAIR_REQ ||
           msg_type == SPROTOCOL_MSG_PAIR_RSP ||
           msg_type == SPROTOCOL_MSG_PAIR_CFM ||
           msg_type == SPROTOCOL_MSG_HEARTBEAT ||
           msg_type == SPROTOCOL_MSG_ACK ||
           msg_type == SPROTOCOL_MSG_NACK;
}

bool sprotocol_should_encrypt(sprotocol_handle_t handle, uint8_t dest_addr, uint8_t msg_type, bool broadcast)
{
    sprotocol_peer_slot_t* peer;

    if (handle == NULL || broadcast || msg_type != SPROTOCOL_MSG_DATA) {
        return false;
    }

    if (!handle->config.encryption_enabled) {
        return false;
    }

    peer = sprotocol_find_peer(handle, dest_addr);
    return peer != NULL &&
           peer->device.pair_status == SPROTOCOL_PAIR_COMPLETE &&
           peer->has_session_key;
}

sprotocol_peer_slot_t* sprotocol_find_peer(sprotocol_handle_t handle, uint8_t addr)
{
    size_t i;

    if (handle == NULL) {
        return NULL;
    }

    for (i = 0; i < SPROTOCOL_INTERNAL_MAX_DEVICES; ++i) {
        if (handle->peers[i].in_use && handle->peers[i].device.addr == addr) {
            return &handle->peers[i];
        }
    }

    return NULL;
}

sprotocol_peer_slot_t* sprotocol_alloc_peer(sprotocol_handle_t handle, uint8_t addr)
{
    sprotocol_peer_slot_t* peer;
    size_t i;

    peer = sprotocol_find_peer(handle, addr);
    if (peer != NULL) {
        return peer;
    }

    for (i = 0; i < SPROTOCOL_INTERNAL_MAX_DEVICES; ++i) {
        if (!handle->peers[i].in_use) {
            memset(&handle->peers[i], 0, sizeof(handle->peers[i]));
            handle->peers[i].in_use = true;
            handle->peers[i].device.addr = addr;
            return &handle->peers[i];
        }
    }

    return NULL;
}

void sprotocol_mark_online(sprotocol_handle_t handle, sprotocol_peer_slot_t* peer, bool online)
{
    uint8_t value;

    if (handle == NULL || peer == NULL) {
        return;
    }

    value = online ? SPROTOCOL_DEVICE_ONLINE : SPROTOCOL_DEVICE_OFFLINE;
    if (peer->device.online == value) {
        if (online) {
            peer->device.last_heartbeat = sprotocol_now_ms(handle);
        }
        return;
    }

    peer->device.online = value;
    if (online) {
        peer->device.last_heartbeat = sprotocol_now_ms(handle);
    }

    if (handle->config.online_cb != NULL) {
        handle->config.online_cb(peer->device.addr, value, handle->config.user_data);
    }
}

void sprotocol_mark_pair_state(sprotocol_handle_t handle, sprotocol_peer_slot_t* peer, uint8_t status)
{
    if (handle == NULL || peer == NULL || peer->device.pair_status == status) {
        return;
    }

    peer->device.pair_status = status;
    if (handle->config.pair_cb != NULL) {
        handle->config.pair_cb(peer->device.addr, status, handle->config.user_data);
    }
}

void sprotocol_reset_peer(sprotocol_handle_t handle, sprotocol_peer_slot_t* peer)
{
    uint8_t old_addr;
    uint8_t old_pair_status;
    uint8_t old_online;

    if (handle == NULL || peer == NULL || !peer->in_use) {
        return;
    }

    old_addr = peer->device.addr;
    old_pair_status = peer->device.pair_status;
    old_online = peer->device.online;
    sprotocol_crypto_peer_reset(peer);
    memset(peer, 0, sizeof(*peer));

    if (old_online == SPROTOCOL_DEVICE_ONLINE && handle->config.online_cb != NULL) {
        handle->config.online_cb(old_addr, SPROTOCOL_DEVICE_OFFLINE, handle->config.user_data);
    }

    if (old_pair_status != SPROTOCOL_PAIR_NONE && handle->config.pair_cb != NULL) {
        handle->config.pair_cb(old_addr, SPROTOCOL_PAIR_NONE, handle->config.user_data);
    }
}

static sprotocol_blacklist_entry_t* sprotocol_find_blacklist_entry(sprotocol_handle_t handle, uint8_t addr)
{
    uint8_t i;

    for (i = 0; i < handle->blacklist_count; ++i) {
        if (handle->blacklist[i].addr == addr) {
            return &handle->blacklist[i];
        }
    }

    return NULL;
}

void sprotocol_blacklist_cleanup(sprotocol_handle_t handle)
{
    uint8_t i = 0;
    uint32_t now;

    if (handle == NULL) {
        return;
    }

    now = sprotocol_now_ms(handle);
    while (i < handle->blacklist_count) {
        if (handle->blacklist[i].expire_time != 0U && handle->blacklist[i].expire_time <= now) {
            uint8_t remaining = (uint8_t)(handle->blacklist_count - i - 1U);
            if (remaining > 0U) {
                memmove(&handle->blacklist[i], &handle->blacklist[i + 1U], remaining * sizeof(handle->blacklist[0]));
            }
            --handle->blacklist_count;
            continue;
        }
        ++i;
    }
}

void sprotocol_note_violation(sprotocol_handle_t handle, uint8_t addr)
{
    sprotocol_peer_slot_t* peer;
    sprotocol_blacklist_entry_t* entry;
    uint8_t i;
    uint32_t now;

    if (handle == NULL || addr == SPROTOCOL_ADDR_BROADCAST) {
        return;
    }

    now = sprotocol_now_ms(handle);
    peer = sprotocol_alloc_peer(handle, addr);
    if (peer == NULL) {
        return;
    }

    if (now - peer->violation_window_start > SPROTOCOL_BLACKLIST_WINDOW) {
        peer->violation_window_start = now;
        peer->violation_count = 0;
    }

    if (peer->violation_count < UINT8_MAX) {
        ++peer->violation_count;
    }

    if (peer->violation_count < SPROTOCOL_BLACKLIST_LIMIT) {
        return;
    }

    entry = sprotocol_find_blacklist_entry(handle, addr);
    if (entry == NULL) {
        if (handle->blacklist_count >= SPROTOCOL_MAX_BLACKLIST) {
            for (i = 1; i < handle->blacklist_count; ++i) {
                handle->blacklist[i - 1U] = handle->blacklist[i];
            }
            --handle->blacklist_count;
        }

        entry = &handle->blacklist[handle->blacklist_count++];
        memset(entry, 0, sizeof(*entry));
        entry->addr = addr;
    }

    entry->add_time = now;
    entry->expire_time = now + SPROTOCOL_BLACKLIST_EXPIRE;
    entry->trigger_count = peer->violation_count;
}

static bool sprotocol_is_persistable_peer(sprotocol_handle_t handle, const sprotocol_peer_slot_t* peer)
{
    if (handle->config.encryption_enabled) {
        return false;
    }

    return peer->in_use && peer->device.pair_status == SPROTOCOL_PAIR_COMPLETE;
}

void sprotocol_save_state(sprotocol_handle_t handle)
{
    sprotocol_persist_record_t records[SPROTOCOL_INTERNAL_MAX_DEVICES];
    size_t i;
    size_t record_count = 0;

    if (handle == NULL || handle->config.flash_write == NULL) {
        return;
    }

    memset(records, 0, sizeof(records));
    for (i = 0; i < SPROTOCOL_INTERNAL_MAX_DEVICES; ++i) {
        if (!sprotocol_is_persistable_peer(handle, &handle->peers[i])) {
            continue;
        }

        records[record_count].magic = SPROTOCOL_PERSIST_MAGIC;
        records[record_count].addr = handle->peers[i].device.addr;
        records[record_count].pair_status = handle->peers[i].device.pair_status;
        records[record_count].seq_tx = handle->peers[i].device.seq_tx;
        records[record_count].seq_rx = handle->peers[i].device.seq_rx;
        ++record_count;
    }

    handle->config.flash_write(0U, (const uint8_t*)records, sizeof(records), handle->config.user_data);
    handle->last_seq_save = sprotocol_now_ms(handle);
}

void sprotocol_load_state(sprotocol_handle_t handle)
{
    sprotocol_persist_record_t records[SPROTOCOL_INTERNAL_MAX_DEVICES];
    size_t i;

    if (handle == NULL || handle->config.flash_read == NULL || handle->config.encryption_enabled) {
        return;
    }

    memset(records, 0, sizeof(records));
    if (handle->config.flash_read(0U, (uint8_t*)records, sizeof(records), handle->config.user_data) != 0) {
        return;
    }

    for (i = 0; i < SPROTOCOL_INTERNAL_MAX_DEVICES; ++i) {
        sprotocol_peer_slot_t* peer;

        if (records[i].magic != SPROTOCOL_PERSIST_MAGIC || records[i].pair_status != SPROTOCOL_PAIR_COMPLETE) {
            continue;
        }

        if (!sprotocol_addr_allowed_for_role(handle, records[i].addr)) {
            continue;
        }

        peer = sprotocol_alloc_peer(handle, records[i].addr);
        if (peer == NULL) {
            continue;
        }

        peer->device.seq_tx = records[i].seq_tx;
        peer->device.seq_rx = records[i].seq_rx;
        peer->device.pair_time = sprotocol_now_ms(handle);
        sprotocol_mark_pair_state(handle, peer, SPROTOCOL_PAIR_COMPLETE);
    }
}

static int sprotocol_prepare_payload(sprotocol_handle_t handle,
                                     sprotocol_peer_slot_t* peer,
                                     sprotocol_frame_t* frame,
                                     const uint8_t* payload,
                                     size_t len)
{
    uint8_t aad[10];
    size_t encrypted_len = 0;
    int rc;

    if (len > SPROTOCOL_PAYLOAD_ENCODE_LIMIT) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }

    if (!frame->flags.encrypted) {
        frame->payload_len = (uint8_t)len;
        if (len > 0U && payload != NULL) {
            memcpy(frame->payload, payload, len);
        }
        return SPROTOCOL_OK;
    }

    if (peer == NULL || payload == NULL) {
        return SPROTOCOL_ERR_INVALID_STATE;
    }

    sprotocol_fill_aad(frame, aad);
    rc = sprotocol_crypto_encrypt(peer, aad, sizeof(aad), payload, len, frame->payload, &encrypted_len);
    if (rc != SPROTOCOL_OK) {
        return rc;
    }

    if (encrypted_len > SPROTOCOL_PAYLOAD_ENCODE_LIMIT) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }

    frame->payload_len = (uint8_t)encrypted_len;
    return SPROTOCOL_OK;
}

int sprotocol_send_frame_internal(sprotocol_handle_t handle,
                                  uint8_t dest_addr,
                                  uint16_t domain_id,
                                  uint8_t msg_type,
                                  const uint8_t* payload,
                                  size_t len,
                                  bool broadcast,
                                  bool allow_unpaired)
{
    sprotocol_frame_t frame;
    sprotocol_wire_frame_t wire;
    sprotocol_peer_slot_t* peer = NULL;
    uint16_t seq = 0;
    int rc;

    if (handle == NULL || handle->config.send_cb == NULL) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }

    if ((payload == NULL && len != 0U) || len > SPROTOCOL_PAYLOAD_ENCODE_LIMIT) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }

    if (!broadcast && !sprotocol_addr_allowed_for_role(handle, dest_addr)) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }

    if (!broadcast) {
        peer = sprotocol_find_peer(handle, dest_addr);
        if (peer == NULL && allow_unpaired) {
            peer = sprotocol_alloc_peer(handle, dest_addr);
        }

        if (!allow_unpaired &&
            (peer == NULL || peer->device.pair_status != SPROTOCOL_PAIR_COMPLETE)) {
            return SPROTOCOL_ERR_NOT_FOUND;
        }
    }

    rc = sprotocol_next_tx_sequence(handle, dest_addr, broadcast, &seq);
    if (rc != SPROTOCOL_OK) {
        return rc;
    }

    memset(&frame, 0, sizeof(frame));
    frame.header = SPROTOCOL_FRAME_HEADER;
    frame.version = SPROTOCOL_FRAME_VERSION;
    frame.flags.broadcast = broadcast ? 1U : 0U;
    frame.flags.encrypted = sprotocol_should_encrypt(handle, dest_addr, msg_type, broadcast) ? 1U : 0U;
    frame.src_addr = handle->config.local_addr;
    frame.dest_addr = broadcast ? SPROTOCOL_ADDR_BROADCAST : dest_addr;
    frame.seq = seq;
    frame.domain_id = domain_id;
    frame.msg_type = msg_type;

    rc = sprotocol_prepare_payload(handle, peer, &frame, payload, len);
    if (rc != SPROTOCOL_OK) {
        return rc;
    }

    rc = sprotocol_build_frame(&frame, &wire);
    if (rc != SPROTOCOL_OK) {
        return rc;
    }

    handle->config.send_cb(wire.data, wire.len, handle->config.user_data);
    return SPROTOCOL_OK;
}

static int sprotocol_handle_data_frame(sprotocol_handle_t handle,
                                       sprotocol_peer_slot_t* peer,
                                       const sprotocol_frame_t* frame)
{
    uint8_t plaintext[SPROTOCOL_MAX_PAYLOAD_LEN];
    const uint8_t* payload = frame->payload;
    size_t payload_len = frame->payload_len;

    if (frame->flags.broadcast) {
        if (frame->flags.encrypted) {
            return SPROTOCOL_ERR_INVALID_STATE;
        }
        return sprotocol_dispatch_recv_callback(handle, frame, payload, payload_len);
    }

    if (peer == NULL || peer->device.pair_status != SPROTOCOL_PAIR_COMPLETE) {
        return SPROTOCOL_ERR_INVALID_STATE;
    }

    if (frame->flags.encrypted) {
        uint8_t aad[10];
        size_t plaintext_len = 0;
        int rc;

        sprotocol_fill_aad(frame, aad);
        rc = sprotocol_crypto_decrypt(peer,
                                      aad,
                                      sizeof(aad),
                                      frame->payload,
                                      frame->payload_len,
                                      plaintext,
                                      &plaintext_len);
        if (rc != SPROTOCOL_OK) {
            return rc;
        }
        payload = plaintext;
        payload_len = plaintext_len;
    }

    sprotocol_mark_online(handle, peer, true);
    return sprotocol_dispatch_recv_callback(handle, frame, payload, payload_len);
}

static int sprotocol_handle_control_frame(sprotocol_handle_t handle,
                                          sprotocol_peer_slot_t* peer,
                                          const sprotocol_frame_t* frame)
{
    (void)peer;

    switch (frame->msg_type) {
        case SPROTOCOL_MSG_PAIR_REQ:
            return sprotocol_handle_pair_request_frame(handle, frame);
        case SPROTOCOL_MSG_PAIR_RSP:
            return sprotocol_handle_pair_response_frame(handle, frame);
        case SPROTOCOL_MSG_PAIR_CFM:
            return sprotocol_handle_pair_confirm_frame(handle, frame);
        case SPROTOCOL_MSG_HEARTBEAT:
            if (peer == NULL || peer->device.pair_status != SPROTOCOL_PAIR_COMPLETE) {
                return SPROTOCOL_ERR_INVALID_STATE;
            }
            sprotocol_mark_online(handle, peer, true);
            return SPROTOCOL_OK;
        case SPROTOCOL_MSG_ACK:
        case SPROTOCOL_MSG_NACK:
            return SPROTOCOL_OK;
        default:
            return SPROTOCOL_ERR_INVALID_ARG;
    }
}

sprotocol_handle_t sprotocol_init(const sprotocol_config_t* config)
{
    sprotocol_handle_t handle;

    if (config == NULL || config->send_cb == NULL) {
        return NULL;
    }

    if (config->role == SPROTOCOL_ROLE_MASTER && config->local_addr != SPROTOCOL_ADDR_MASTER) {
        return NULL;
    }

    if (config->role == SPROTOCOL_ROLE_SLAVE && !sprotocol_is_slave_addr(config->local_addr)) {
        return NULL;
    }

    handle = (sprotocol_handle_t)calloc(1U, sizeof(*handle));
    if (handle == NULL) {
        return NULL;
    }

    handle->config = *config;
    if (handle->config.heartbeat_timeout == 0U) {
        handle->config.heartbeat_timeout = 3000U;
    }
    if (handle->config.pair_timeout == 0U) {
        handle->config.pair_timeout = 5000U;
    }
    if (handle->config.max_slaves == 0U || handle->config.max_slaves > SPROTOCOL_MAX_SLAVES) {
        handle->config.max_slaves = SPROTOCOL_MAX_SLAVES;
    }

    if (handle->config.encryption_enabled) {
        handle->config.enc_type = SPROTOCOL_ENC_ECC;
        if (sprotocol_crypto_global_init() != SPROTOCOL_OK) {
            free(handle);
            return NULL;
        }
    }

    sprotocol_load_state(handle);
    return handle;
}

void sprotocol_deinit(sprotocol_handle_t handle)
{
    size_t i;

    if (handle == NULL) {
        return;
    }

    sprotocol_save_state(handle);
    for (i = 0; i < SPROTOCOL_INTERNAL_MAX_DEVICES; ++i) {
        sprotocol_crypto_peer_reset(&handle->peers[i]);
    }
    free(handle);
}

void sprotocol_poll(sprotocol_handle_t handle)
{
    size_t i;
    uint32_t now;

    if (handle == NULL) {
        return;
    }

    now = sprotocol_now_ms(handle);
    sprotocol_blacklist_cleanup(handle);

    for (i = 0; i < SPROTOCOL_INTERNAL_MAX_DEVICES; ++i) {
        sprotocol_peer_slot_t* peer = &handle->peers[i];

        if (!peer->in_use) {
            continue;
        }

        if (peer->device.pair_status == SPROTOCOL_PAIR_PENDING &&
            now - peer->pending_since >= handle->config.pair_timeout) {
            sprotocol_reset_peer(handle, peer);
            continue;
        }

        if (handle->config.role == SPROTOCOL_ROLE_MASTER &&
            peer->device.pair_status == SPROTOCOL_PAIR_COMPLETE &&
            peer->device.online == SPROTOCOL_DEVICE_ONLINE &&
            now - peer->device.last_heartbeat >= handle->config.heartbeat_timeout) {
            sprotocol_mark_online(handle, peer, false);
        }
    }

    if (handle->config.seq_save_interval != 0U &&
        now - handle->last_seq_save >= handle->config.seq_save_interval) {
        sprotocol_save_state(handle);
    }
}

void sprotocol_input(sprotocol_handle_t handle, const uint8_t* data, size_t len)
{
    sprotocol_frame_t frame;
    sprotocol_peer_slot_t* peer = NULL;
    int rc;

    if (handle == NULL || data == NULL || len == 0U) {
        return;
    }

    rc = sprotocol_parse_frame(data, len, &frame);
    if (rc != SPROTOCOL_OK) {
        return;
    }

    if (frame.dest_addr != handle->config.local_addr && frame.dest_addr != SPROTOCOL_ADDR_BROADCAST) {
        return;
    }

    sprotocol_blacklist_cleanup(handle);
    if (sprotocol_is_blacklisted(handle, frame.src_addr)) {
        return;
    }

    if (!sprotocol_addr_allowed_for_role(handle, frame.src_addr)) {
        sprotocol_note_violation(handle, frame.src_addr);
        return;
    }

    if (!frame.flags.broadcast) {
        peer = sprotocol_find_peer(handle, frame.src_addr);
        if (peer == NULL && frame.msg_type == SPROTOCOL_MSG_PAIR_REQ && handle->config.role == SPROTOCOL_ROLE_SLAVE) {
            peer = sprotocol_alloc_peer(handle, frame.src_addr);
        }
        if (peer == NULL && frame.msg_type != SPROTOCOL_MSG_PAIR_REQ) {
            sprotocol_note_violation(handle, frame.src_addr);
            return;
        }
        if (peer != NULL) {
            rc = sprotocol_validate_rx_sequence(peer, &frame);
            if (rc != SPROTOCOL_OK) {
                sprotocol_note_violation(handle, frame.src_addr);
                return;
            }
        }
    }

    if (sprotocol_is_control_msg(frame.msg_type)) {
        rc = sprotocol_handle_control_frame(handle, peer, &frame);
    } else {
        rc = sprotocol_handle_data_frame(handle, peer, &frame);
    }

    if (rc != SPROTOCOL_OK) {
        sprotocol_note_violation(handle, frame.src_addr);
    }
}

int sprotocol_get_paired_devices(sprotocol_handle_t handle, uint8_t* addrs, uint8_t max_count)
{
    size_t i;
    uint8_t count = 0;

    if (handle == NULL) {
        return 0;
    }

    for (i = 0; i < SPROTOCOL_INTERNAL_MAX_DEVICES; ++i) {
        if (!handle->peers[i].in_use || handle->peers[i].device.pair_status != SPROTOCOL_PAIR_COMPLETE) {
            continue;
        }

        if (addrs != NULL && count < max_count) {
            addrs[count] = handle->peers[i].device.addr;
        }
        ++count;
    }

    return count;
}

const sprotocol_device_t* sprotocol_get_device(sprotocol_handle_t handle, uint8_t addr)
{
    sprotocol_peer_slot_t* peer;

    if (handle == NULL) {
        return NULL;
    }

    peer = sprotocol_find_peer(handle, addr);
    return peer == NULL ? NULL : &peer->device;
}

int sprotocol_send(sprotocol_handle_t handle,
                   uint8_t dest_addr,
                   uint16_t domain_id,
                   uint8_t msg_type,
                   const uint8_t* payload,
                   size_t len)
{
    if (dest_addr == SPROTOCOL_ADDR_BROADCAST) {
        return sprotocol_broadcast(handle, domain_id, msg_type, payload, len);
    }

    return sprotocol_send_frame_internal(handle, dest_addr, domain_id, msg_type, payload, len, false, false);
}

int sprotocol_broadcast(sprotocol_handle_t handle,
                        uint16_t domain_id,
                        uint8_t msg_type,
                        const uint8_t* payload,
                        size_t len)
{
    if (handle == NULL || handle->config.role != SPROTOCOL_ROLE_MASTER) {
        return SPROTOCOL_ERR_INVALID_STATE;
    }

    return sprotocol_send_frame_internal(handle,
                                         SPROTOCOL_ADDR_BROADCAST,
                                         domain_id,
                                         msg_type,
                                         payload,
                                         len,
                                         true,
                                         true);
}

int sprotocol_send_heartbeat(sprotocol_handle_t handle)
{
    if (handle == NULL || handle->config.role != SPROTOCOL_ROLE_SLAVE) {
        return SPROTOCOL_ERR_INVALID_STATE;
    }

    return sprotocol_send_frame_internal(handle,
                                         SPROTOCOL_ADDR_MASTER,
                                         SPROTOCOL_DOMAIN_BASE,
                                         SPROTOCOL_MSG_HEARTBEAT,
                                         NULL,
                                         0U,
                                         false,
                                         false);
}

int sprotocol_is_device_online(sprotocol_handle_t handle, uint8_t addr)
{
    const sprotocol_device_t* device = sprotocol_get_device(handle, addr);
    return device != NULL && device->online == SPROTOCOL_DEVICE_ONLINE;
}

uint16_t sprotocol_get_tx_seq(sprotocol_handle_t handle, uint8_t addr)
{
    const sprotocol_device_t* device = sprotocol_get_device(handle, addr);
    return device == NULL ? 0U : device->seq_tx;
}

void sprotocol_set_seq_save_interval(sprotocol_handle_t handle, uint16_t interval_ms)
{
    if (handle == NULL) {
        return;
    }

    handle->config.seq_save_interval = interval_ms;
}

int sprotocol_is_blacklisted(sprotocol_handle_t handle, uint8_t addr)
{
    sprotocol_blacklist_entry_t* entry;

    if (handle == NULL) {
        return 0;
    }

    sprotocol_blacklist_cleanup(handle);
    entry = sprotocol_find_blacklist_entry(handle, addr);
    return entry != NULL ? 1 : 0;
}

int sprotocol_get_blacklist_count(sprotocol_handle_t handle)
{
    if (handle == NULL) {
        return 0;
    }

    sprotocol_blacklist_cleanup(handle);
    return handle->blacklist_count;
}

const char* sprotocol_get_version(void)
{
    return "1.0.0";
}
