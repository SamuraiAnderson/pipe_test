#include "sprotocol_internal.h"

static void send_pair_frame(struct sprotocol_handle *h, uint8_t dest_addr,
                            uint8_t msg_type, const uint8_t *payload, size_t len)
{
    sprotocol_frame_t frame;
    memset(&frame, 0, sizeof(frame));
    frame.header    = SPROTOCOL_FRAME_HEADER;
    frame.version   = SPROTOCOL_FRAME_VERSION;
    frame.src_addr  = h->config.local_addr;
    frame.dest_addr = dest_addr;
    frame.seq       = h->local_seq++;
    frame.domain_id = SPROTOCOL_DOMAIN_BASE;
    frame.msg_type  = msg_type;

    if (payload && len > 0 && len <= SPROTOCOL_MAX_PAYLOAD_LEN) {
        memcpy(frame.payload, payload, len);
        frame.payload_len = (uint8_t)len;
    }

    sprotocol_send_frame(h, &frame);
}

static void handle_pair_req(struct sprotocol_handle *h, const sprotocol_frame_t *frame)
{
    /* Only slaves handle pair requests */
    if (h->config.role != SPROTOCOL_ROLE_SLAVE)
        return;

    /* The request must target us or broadcast */
    if (frame->dest_addr != h->config.local_addr &&
        frame->dest_addr != SPROTOCOL_ADDR_BROADCAST)
        return;

    uint8_t master_addr = frame->src_addr;

    int idx = sprotocol_find_device(h, master_addr);
    if (idx < 0) {
        idx = sprotocol_add_device(h, master_addr);
        if (idx < 0)
            return;
    }

    uint32_t now = h->config.get_time ? h->config.get_time() : 0;
    h->devices[idx].pair_status = SPROTOCOL_PAIR_PENDING;
    h->devices[idx].pair_time   = now;

    /* If encryption enabled, compute shared secret from master's pubkey in payload */
    if (h->config.encryption_enabled && h->crypto_initialized) {
        if (frame->payload_len >= SPROTOCOL_ECDH_PUBKEY_LEN) {
            sprotocol_crypto_compute_shared(h, idx,
                                            frame->payload, frame->payload_len);
        }
    }

    /* Auto-respond with PAIR_RSP, include our public key if encryption is on */
    if (h->config.encryption_enabled && h->crypto_initialized) {
        uint8_t pubkey[SPROTOCOL_ECDH_PUBKEY_LEN];
        size_t pubkey_len = sizeof(pubkey);
        if (sprotocol_crypto_get_pubkey(h, pubkey, &pubkey_len) == SPROTOCOL_OK) {
            send_pair_frame(h, master_addr, SPROTOCOL_MSG_PAIR_RSP, pubkey, pubkey_len);
        } else {
            send_pair_frame(h, master_addr, SPROTOCOL_MSG_PAIR_RSP, NULL, 0);
        }
    } else {
        send_pair_frame(h, master_addr, SPROTOCOL_MSG_PAIR_RSP, NULL, 0);
    }
}

static void handle_pair_rsp(struct sprotocol_handle *h, const sprotocol_frame_t *frame)
{
    /* Only master handles pair responses */
    if (h->config.role != SPROTOCOL_ROLE_MASTER)
        return;

    uint8_t slave_addr = frame->src_addr;
    int idx = sprotocol_find_device(h, slave_addr);
    if (idx < 0)
        return;

    if (h->devices[idx].pair_status != SPROTOCOL_PAIR_PENDING)
        return;

    /* If encryption enabled, compute shared secret from slave's pubkey */
    if (h->config.encryption_enabled && h->crypto_initialized) {
        if (frame->payload_len >= SPROTOCOL_ECDH_PUBKEY_LEN) {
            sprotocol_crypto_compute_shared(h, idx,
                                            frame->payload, frame->payload_len);
        }
    }

    /* Mark complete and send confirmation */
    h->devices[idx].pair_status = SPROTOCOL_PAIR_COMPLETE;
    h->devices[idx].online = SPROTOCOL_DEVICE_ONLINE;
    uint32_t now = h->config.get_time ? h->config.get_time() : 0;
    h->devices[idx].last_heartbeat = now;

    send_pair_frame(h, slave_addr, SPROTOCOL_MSG_PAIR_CFM, NULL, 0);

    if (h->config.pair_cb)
        h->config.pair_cb(slave_addr, SPROTOCOL_PAIR_COMPLETE, h->config.user_data);
}

static void handle_pair_cfm(struct sprotocol_handle *h, const sprotocol_frame_t *frame)
{
    /* Only slaves handle pair confirms */
    if (h->config.role != SPROTOCOL_ROLE_SLAVE)
        return;

    uint8_t master_addr = frame->src_addr;
    int idx = sprotocol_find_device(h, master_addr);
    if (idx < 0)
        return;

    h->devices[idx].pair_status = SPROTOCOL_PAIR_COMPLETE;
    h->devices[idx].online = SPROTOCOL_DEVICE_ONLINE;
    uint32_t now = h->config.get_time ? h->config.get_time() : 0;
    h->devices[idx].last_heartbeat = now;

    if (h->config.pair_cb)
        h->config.pair_cb(master_addr, SPROTOCOL_PAIR_COMPLETE, h->config.user_data);
}

void sprotocol_pair_handle_input(struct sprotocol_handle *h, const sprotocol_frame_t *frame)
{
    switch (frame->msg_type) {
    case SPROTOCOL_MSG_PAIR_REQ:
        handle_pair_req(h, frame);
        break;
    case SPROTOCOL_MSG_PAIR_RSP:
        handle_pair_rsp(h, frame);
        break;
    case SPROTOCOL_MSG_PAIR_CFM:
        handle_pair_cfm(h, frame);
        break;
    default:
        break;
    }
}

void sprotocol_pair_poll(struct sprotocol_handle *h, uint32_t now)
{
    uint32_t timeout = h->config.pair_timeout;
    if (timeout == 0)
        timeout = 5000;

    for (int i = 0; i < h->device_count; i++) {
        if (h->devices[i].pair_status == SPROTOCOL_PAIR_PENDING) {
            if (now - h->devices[i].pair_time > timeout) {
                h->devices[i].pair_status = SPROTOCOL_PAIR_NONE;
                if (h->config.pair_cb) {
                    h->config.pair_cb(h->devices[i].addr, SPROTOCOL_PAIR_NONE,
                                      h->config.user_data);
                }
            }
        }
    }
}

/*============================================================================
 * Public pairing API
 *============================================================================*/

int sprotocol_pair_request(sprotocol_handle_t handle, uint8_t slave_addr)
{
    if (!handle)
        return SPROTOCOL_ERR_INVALID_ARG;
    struct sprotocol_handle *h = handle;

    if (h->config.role != SPROTOCOL_ROLE_MASTER)
        return SPROTOCOL_ERR_INVALID_STATE;

    if (!sprotocol_is_valid_slave_addr(slave_addr))
        return SPROTOCOL_ERR_INVALID_ARG;

    if (h->device_count >= h->config.max_slaves)
        return SPROTOCOL_ERR_FULL;

    /* Check if already paired or pending */
    int idx = sprotocol_find_device(h, slave_addr);
    if (idx >= 0 && h->devices[idx].pair_status == SPROTOCOL_PAIR_COMPLETE)
        return SPROTOCOL_OK;

    if (idx < 0) {
        idx = sprotocol_add_device(h, slave_addr);
        if (idx < 0)
            return SPROTOCOL_ERR_FULL;
    }

    uint32_t now = h->config.get_time ? h->config.get_time() : 0;
    h->devices[idx].pair_status = SPROTOCOL_PAIR_PENDING;
    h->devices[idx].pair_time   = now;

    /* Send PAIR_REQ, include our public key if encryption enabled */
    if (h->config.encryption_enabled && h->crypto_initialized) {
        uint8_t pubkey[SPROTOCOL_ECDH_PUBKEY_LEN];
        size_t pubkey_len = sizeof(pubkey);
        if (sprotocol_crypto_get_pubkey(h, pubkey, &pubkey_len) == SPROTOCOL_OK) {
            send_pair_frame(h, slave_addr, SPROTOCOL_MSG_PAIR_REQ, pubkey, pubkey_len);
        } else {
            send_pair_frame(h, slave_addr, SPROTOCOL_MSG_PAIR_REQ, NULL, 0);
        }
    } else {
        send_pair_frame(h, slave_addr, SPROTOCOL_MSG_PAIR_REQ, NULL, 0);
    }

    return SPROTOCOL_OK;
}

int sprotocol_remove_device(sprotocol_handle_t handle, uint8_t addr)
{
    if (!handle)
        return SPROTOCOL_ERR_INVALID_ARG;
    struct sprotocol_handle *h = handle;

    int idx = sprotocol_find_device(h, addr);
    if (idx < 0)
        return SPROTOCOL_ERR_NOT_FOUND;

    /* Shift remaining entries down */
    for (int i = idx; i < h->device_count - 1; i++) {
        h->devices[i] = h->devices[i + 1];
        h->device_crypto[i] = h->device_crypto[i + 1];
    }
    h->device_count--;

    memset(&h->devices[h->device_count], 0, sizeof(sprotocol_device_t));
    memset(&h->device_crypto[h->device_count], 0, sizeof(sprotocol_device_crypto_t));

    return SPROTOCOL_OK;
}

void sprotocol_remove_all_devices(sprotocol_handle_t handle)
{
    if (!handle)
        return;
    struct sprotocol_handle *h = handle;
    memset(h->devices, 0, sizeof(h->devices));
    memset(h->device_crypto, 0, sizeof(h->device_crypto));
    h->device_count = 0;
}

int sprotocol_get_paired_devices(sprotocol_handle_t handle, uint8_t *addrs, uint8_t max_count)
{
    if (!handle || !addrs)
        return 0;
    struct sprotocol_handle *h = handle;

    int count = 0;
    for (int i = 0; i < h->device_count && count < max_count; i++) {
        if (h->devices[i].pair_status == SPROTOCOL_PAIR_COMPLETE) {
            addrs[count++] = h->devices[i].addr;
        }
    }
    return count;
}

const sprotocol_device_t *sprotocol_get_device(sprotocol_handle_t handle, uint8_t addr)
{
    if (!handle)
        return NULL;
    struct sprotocol_handle *h = handle;

    int idx = sprotocol_find_device(h, addr);
    if (idx < 0)
        return NULL;
    return &h->devices[idx];
}
