#include "sprotocol_internal.h"

sprotocol_handle_t sprotocol_init(const sprotocol_config_t *config)
{
    if (!config || !config->send_cb)
        return NULL;

    if (config->role == SPROTOCOL_ROLE_MASTER && config->local_addr != SPROTOCOL_ADDR_MASTER)
        return NULL;

    uint8_t max_slaves = config->max_slaves;
    if (max_slaves == 0)
        max_slaves = SPROTOCOL_MAX_SLAVES;
    if (max_slaves > SPROTOCOL_MAX_SLAVES)
        max_slaves = SPROTOCOL_MAX_SLAVES;

    struct sprotocol_handle *h = calloc(1, sizeof(struct sprotocol_handle));
    if (!h)
        return NULL;

    h->config = *config;
    h->config.max_slaves = max_slaves;

    if (h->config.heartbeat_timeout == 0)
        h->config.heartbeat_timeout = 3000;
    if (h->config.pair_timeout == 0)
        h->config.pair_timeout = 5000;

    if (config->encryption_enabled) {
        if (sprotocol_crypto_init(h) != SPROTOCOL_OK) {
            free(h);
            return NULL;
        }
    }

    return h;
}

void sprotocol_deinit(sprotocol_handle_t handle)
{
    if (!handle)
        return;
    struct sprotocol_handle *h = handle;

    if (h->crypto_initialized)
        sprotocol_crypto_deinit(h);

    free(h);
}

/*============================================================================
 * Blacklist management
 *============================================================================*/

static void blacklist_check_expiry(struct sprotocol_handle *h, uint32_t now)
{
    for (int i = 0; i < h->blacklist_count; ) {
        if (now >= h->blacklist[i].expire_time) {
            for (int j = i; j < h->blacklist_count - 1; j++)
                h->blacklist[j] = h->blacklist[j + 1];
            h->blacklist_count--;
        } else {
            i++;
        }
    }
}

static void blacklist_record_violation(struct sprotocol_handle *h, uint8_t addr, uint32_t now)
{
    /* Find existing entry */
    for (int i = 0; i < h->blacklist_count; i++) {
        if (h->blacklist[i].addr == addr) {
            h->blacklist[i].trigger_count++;
            return;
        }
    }

    /* Add new entry if limit reached via external trigger tracking */
    if (h->blacklist_count < SPROTOCOL_MAX_BLACKLIST) {
        sprotocol_blacklist_entry_t *e = &h->blacklist[h->blacklist_count];
        e->addr = addr;
        e->add_time = now;
        e->expire_time = now + SPROTOCOL_BLACKLIST_EXPIRE;
        e->trigger_count = 1;
        h->blacklist_count++;
    }
}

int sprotocol_is_blacklisted(sprotocol_handle_t handle, uint8_t addr)
{
    if (!handle)
        return 0;
    struct sprotocol_handle *h = handle;
    for (int i = 0; i < h->blacklist_count; i++) {
        if (h->blacklist[i].addr == addr)
            return 1;
    }
    return 0;
}

int sprotocol_get_blacklist_count(sprotocol_handle_t handle)
{
    if (!handle)
        return 0;
    return ((struct sprotocol_handle *)handle)->blacklist_count;
}

/*============================================================================
 * Heartbeat
 *============================================================================*/

static void heartbeat_poll(struct sprotocol_handle *h, uint32_t now)
{
    if (h->config.role != SPROTOCOL_ROLE_MASTER)
        return;

    for (int i = 0; i < h->device_count; i++) {
        if (h->devices[i].pair_status != SPROTOCOL_PAIR_COMPLETE)
            continue;
        if (h->devices[i].online == SPROTOCOL_DEVICE_OFFLINE)
            continue;

        if (now - h->devices[i].last_heartbeat > h->config.heartbeat_timeout) {
            h->devices[i].online = SPROTOCOL_DEVICE_OFFLINE;
            if (h->config.online_cb) {
                h->config.online_cb(h->devices[i].addr, SPROTOCOL_DEVICE_OFFLINE,
                                    h->config.user_data);
            }
        }
    }
}

int sprotocol_send_heartbeat(sprotocol_handle_t handle)
{
    if (!handle)
        return SPROTOCOL_ERR_INVALID_ARG;
    struct sprotocol_handle *h = handle;

    if (h->config.role != SPROTOCOL_ROLE_SLAVE)
        return SPROTOCOL_ERR_INVALID_STATE;

    /* Find the paired master */
    int idx = -1;
    for (int i = 0; i < h->device_count; i++) {
        if (h->devices[i].pair_status == SPROTOCOL_PAIR_COMPLETE) {
            idx = i;
            break;
        }
    }
    if (idx < 0)
        return SPROTOCOL_ERR_NOT_FOUND;

    sprotocol_frame_t frame;
    memset(&frame, 0, sizeof(frame));
    frame.header    = SPROTOCOL_FRAME_HEADER;
    frame.version   = SPROTOCOL_FRAME_VERSION;
    frame.src_addr  = h->config.local_addr;
    frame.dest_addr = h->devices[idx].addr;
    frame.seq       = h->local_seq++;
    frame.domain_id = SPROTOCOL_DOMAIN_BASE;
    frame.msg_type  = SPROTOCOL_MSG_HEARTBEAT;

    sprotocol_send_frame(h, &frame);
    return SPROTOCOL_OK;
}

int sprotocol_is_device_online(sprotocol_handle_t handle, uint8_t addr)
{
    if (!handle)
        return 0;
    struct sprotocol_handle *h = handle;
    int idx = sprotocol_find_device(h, addr);
    if (idx < 0)
        return 0;
    return h->devices[idx].online == SPROTOCOL_DEVICE_ONLINE ? 1 : 0;
}

/*============================================================================
 * Sequence number management
 *============================================================================*/

uint16_t sprotocol_get_tx_seq(sprotocol_handle_t handle, uint8_t addr)
{
    if (!handle)
        return 0;
    struct sprotocol_handle *h = handle;

    /* For local seq */
    if (addr == h->config.local_addr)
        return h->local_seq;

    int idx = sprotocol_find_device(h, addr);
    if (idx < 0)
        return 0;
    return h->devices[idx].seq_tx;
}

void sprotocol_set_seq_save_interval(sprotocol_handle_t handle, uint16_t interval_ms)
{
    if (!handle)
        return;
    struct sprotocol_handle *h = handle;
    h->config.seq_save_interval = interval_ms;
}

/*============================================================================
 * Data send/receive
 *============================================================================*/

int sprotocol_send(sprotocol_handle_t handle, uint8_t dest_addr, uint16_t domain_id,
                   uint8_t msg_type, const uint8_t *payload, size_t len)
{
    if (!handle)
        return SPROTOCOL_ERR_INVALID_ARG;
    struct sprotocol_handle *h = handle;

    if (len > SPROTOCOL_MAX_PAYLOAD_LEN)
        return SPROTOCOL_ERR_INVALID_ARG;

    int idx = sprotocol_find_device(h, dest_addr);
    if (idx < 0 && dest_addr != SPROTOCOL_ADDR_BROADCAST)
        return SPROTOCOL_ERR_NOT_FOUND;

    if (idx >= 0 && h->devices[idx].pair_status != SPROTOCOL_PAIR_COMPLETE)
        return SPROTOCOL_ERR_INVALID_STATE;

    sprotocol_frame_t frame;
    memset(&frame, 0, sizeof(frame));
    frame.header    = SPROTOCOL_FRAME_HEADER;
    frame.version   = SPROTOCOL_FRAME_VERSION;
    frame.src_addr  = h->config.local_addr;
    frame.dest_addr = dest_addr;
    frame.seq       = h->local_seq++;
    frame.domain_id = domain_id;
    frame.msg_type  = msg_type;

    /* Encrypt payload if encryption is enabled and key is established */
    if (h->config.encryption_enabled && idx >= 0 &&
        h->device_crypto[idx].key_established) {
        uint8_t ct[SPROTOCOL_MAX_PAYLOAD_LEN + SPROTOCOL_GCM_TAG_LEN];
        size_t ct_len = 0;
        int ret = sprotocol_crypto_encrypt(h, idx,
                                           frame.seq, frame.src_addr, frame.dest_addr,
                                           payload, len,
                                           ct, sizeof(ct), &ct_len);
        if (ret != SPROTOCOL_OK)
            return ret;
        if (ct_len > SPROTOCOL_MAX_PAYLOAD_LEN)
            return SPROTOCOL_ERR_INVALID_ARG;
        memcpy(frame.payload, ct, ct_len);
        frame.payload_len = (uint8_t)ct_len;
        frame.flags.encrypted = 1;
    } else {
        if (payload && len > 0)
            memcpy(frame.payload, payload, len);
        frame.payload_len = (uint8_t)len;
    }

    if (idx >= 0)
        h->devices[idx].seq_tx = frame.seq;

    sprotocol_send_frame(h, &frame);
    return SPROTOCOL_OK;
}

int sprotocol_broadcast(sprotocol_handle_t handle, uint16_t domain_id,
                        uint8_t msg_type, const uint8_t *payload, size_t len)
{
    if (!handle)
        return SPROTOCOL_ERR_INVALID_ARG;
    struct sprotocol_handle *h = handle;

    if (len > SPROTOCOL_MAX_PAYLOAD_LEN)
        return SPROTOCOL_ERR_INVALID_ARG;

    sprotocol_frame_t frame;
    memset(&frame, 0, sizeof(frame));
    frame.header         = SPROTOCOL_FRAME_HEADER;
    frame.version        = SPROTOCOL_FRAME_VERSION;
    frame.flags.broadcast = 1;
    frame.src_addr       = h->config.local_addr;
    frame.dest_addr      = SPROTOCOL_ADDR_BROADCAST;
    frame.seq            = h->local_seq++;
    frame.domain_id      = domain_id;
    frame.msg_type       = msg_type;

    if (payload && len > 0)
        memcpy(frame.payload, payload, len);
    frame.payload_len = (uint8_t)len;

    sprotocol_send_frame(h, &frame);
    return SPROTOCOL_OK;
}

/*============================================================================
 * Input processing
 *============================================================================*/

static void handle_heartbeat(struct sprotocol_handle *h, const sprotocol_frame_t *frame)
{
    if (h->config.role != SPROTOCOL_ROLE_MASTER)
        return;

    int idx = sprotocol_find_device(h, frame->src_addr);
    if (idx < 0)
        return;

    uint32_t now = h->config.get_time ? h->config.get_time() : 0;
    uint8_t was_online = h->devices[idx].online;
    h->devices[idx].last_heartbeat = now;
    h->devices[idx].online = SPROTOCOL_DEVICE_ONLINE;

    if (was_online == SPROTOCOL_DEVICE_OFFLINE && h->config.online_cb) {
        h->config.online_cb(frame->src_addr, SPROTOCOL_DEVICE_ONLINE,
                            h->config.user_data);
    }
}

static void handle_data(struct sprotocol_handle *h, const sprotocol_frame_t *frame)
{
    const uint8_t *payload = frame->payload;
    size_t payload_len = frame->payload_len;
    uint8_t decrypted[SPROTOCOL_MAX_PAYLOAD_LEN];

    if (frame->flags.encrypted) {
        int idx = sprotocol_find_device(h, frame->src_addr);
        if (idx < 0)
            return;

        size_t pt_len = 0;
        int ret = sprotocol_crypto_decrypt(h, idx,
                                           frame->seq, frame->src_addr, frame->dest_addr,
                                           payload, payload_len,
                                           decrypted, sizeof(decrypted), &pt_len);
        if (ret != SPROTOCOL_OK)
            return;
        payload = decrypted;
        payload_len = pt_len;
    }

    if (h->config.recv_cb) {
        h->config.recv_cb(frame->src_addr, frame->domain_id,
                          frame->msg_type, payload, payload_len,
                          h->config.user_data);
    }
}

void sprotocol_input(sprotocol_handle_t handle, const uint8_t *data, size_t len)
{
    if (!handle || !data || len == 0)
        return;
    struct sprotocol_handle *h = handle;

    sprotocol_frame_t frame;
    if (sprotocol_frame_decode(data, len, &frame) != SPROTOCOL_OK)
        return;

    /* Check destination: must be for us or broadcast */
    if (frame.dest_addr != h->config.local_addr &&
        frame.dest_addr != SPROTOCOL_ADDR_BROADCAST)
        return;

    uint32_t now = h->config.get_time ? h->config.get_time() : 0;

    /* Check blacklist */
    if (sprotocol_is_blacklisted(handle, frame.src_addr))
        return;

    /* Sequence number validation for paired devices */
    int idx = sprotocol_find_device(h, frame.src_addr);
    if (idx >= 0 && h->devices[idx].pair_status == SPROTOCOL_PAIR_COMPLETE) {
        /* Accept if seq > last received (with wraparound tolerance) */
        uint16_t expected = h->devices[idx].seq_rx;
        int16_t diff = (int16_t)(frame.seq - expected);
        if (diff < 0 && frame.msg_type == SPROTOCOL_MSG_DATA) {
            blacklist_record_violation(h, frame.src_addr, now);
            return;
        }
        h->devices[idx].seq_rx = frame.seq + 1;
    }

    /* Dispatch by message type */
    switch (frame.msg_type) {
    case SPROTOCOL_MSG_PAIR_REQ:
    case SPROTOCOL_MSG_PAIR_RSP:
    case SPROTOCOL_MSG_PAIR_CFM:
        sprotocol_pair_handle_input(h, &frame);
        break;
    case SPROTOCOL_MSG_HEARTBEAT:
        handle_heartbeat(h, &frame);
        break;
    case SPROTOCOL_MSG_DATA:
        handle_data(h, &frame);
        break;
    default:
        break;
    }
}

/*============================================================================
 * Poll
 *============================================================================*/

void sprotocol_poll(sprotocol_handle_t handle)
{
    if (!handle)
        return;
    struct sprotocol_handle *h = handle;
    uint32_t now = h->config.get_time ? h->config.get_time() : 0;

    sprotocol_pair_poll(h, now);
    heartbeat_poll(h, now);
    blacklist_check_expiry(h, now);

    /* Periodic sequence number save */
    if (h->config.flash_write && h->config.seq_save_interval > 0) {
        if (now - h->last_seq_save_time >= h->config.seq_save_interval) {
            h->config.flash_write(0, (const uint8_t *)&h->local_seq,
                                  sizeof(h->local_seq), h->config.user_data);
            h->last_seq_save_time = now;
        }
    }
}
