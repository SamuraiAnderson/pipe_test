#include "sprotocol_internal.h"
#include <stdio.h>

/* CRC-16/CCITT (polynomial 0x1021, init 0xFFFF) */
uint16_t sprotocol_crc16(const uint8_t *data, size_t len)
{
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint16_t)data[i] << 8;
        for (int j = 0; j < 8; j++) {
            if (crc & 0x8000)
                crc = (crc << 1) ^ 0x1021;
            else
                crc <<= 1;
        }
    }
    return crc;
}

static uint8_t flags_to_byte(const sprotocol_flags_t *f)
{
    uint8_t b = 0;
    b |= (f->broadcast & 1);
    b |= (f->need_ack & 1)   << 1;
    b |= (f->encrypted & 1)  << 2;
    b |= (f->retransmit & 1) << 3;
    b |= (f->fragmented & 1) << 4;
    b |= (f->reserved & 7)   << 5;
    return b;
}

static void byte_to_flags(uint8_t b, sprotocol_flags_t *f)
{
    f->broadcast  = b & 1;
    f->need_ack   = (b >> 1) & 1;
    f->encrypted  = (b >> 2) & 1;
    f->retransmit = (b >> 3) & 1;
    f->fragmented = (b >> 4) & 1;
    f->reserved   = (b >> 5) & 7;
}

/**
 * Encode frame to wire format. Returns number of bytes written, 0 on error.
 *
 * Wire layout:
 *   header(1) version(1) flags(1) src_addr(1) dest_addr(1) seq(2,LE)
 *   domain_id(2,LE) msg_type(1) payload_len(1) payload(N) crc16(2,LE)
 */
size_t sprotocol_frame_encode(const sprotocol_frame_t *frame, uint8_t *buf, size_t buf_size)
{
    size_t total = SPROTOCOL_FRAME_OVERHEAD + frame->payload_len + 2;
    if (!frame || !buf || buf_size < total)
        return 0;

    size_t pos = 0;
    buf[pos++] = frame->header;
    buf[pos++] = frame->version;
    buf[pos++] = flags_to_byte(&frame->flags);
    buf[pos++] = frame->src_addr;
    buf[pos++] = frame->dest_addr;
    buf[pos++] = (uint8_t)(frame->seq & 0xFF);
    buf[pos++] = (uint8_t)(frame->seq >> 8);
    buf[pos++] = (uint8_t)(frame->domain_id & 0xFF);
    buf[pos++] = (uint8_t)(frame->domain_id >> 8);
    buf[pos++] = frame->msg_type;
    buf[pos++] = frame->payload_len;

    if (frame->payload_len > 0)
        memcpy(&buf[pos], frame->payload, frame->payload_len);
    pos += frame->payload_len;

    /* CRC covers everything before the CRC field */
    uint16_t crc = sprotocol_crc16(buf, pos);
    buf[pos++] = (uint8_t)(crc & 0xFF);
    buf[pos++] = (uint8_t)(crc >> 8);

    return pos;
}

/**
 * Decode wire bytes into a frame struct. Returns 0 on success, negative on error.
 */
int sprotocol_frame_decode(const uint8_t *buf, size_t len, sprotocol_frame_t *frame)
{
    if (!buf || !frame || len < SPROTOCOL_FRAME_OVERHEAD + 2)
        return SPROTOCOL_ERR_INVALID_ARG;

    size_t pos = 0;
    frame->header = buf[pos++];
    if (frame->header != SPROTOCOL_FRAME_HEADER)
        return SPROTOCOL_ERR_INVALID_ARG;

    frame->version = buf[pos++];
    byte_to_flags(buf[pos++], &frame->flags);
    frame->src_addr  = buf[pos++];
    frame->dest_addr = buf[pos++];
    frame->seq       = (uint16_t)buf[pos] | ((uint16_t)buf[pos + 1] << 8);
    pos += 2;
    frame->domain_id = (uint16_t)buf[pos] | ((uint16_t)buf[pos + 1] << 8);
    pos += 2;
    frame->msg_type    = buf[pos++];
    frame->payload_len = buf[pos++];

    if (len < SPROTOCOL_FRAME_OVERHEAD + frame->payload_len + 2)
        return SPROTOCOL_ERR_INVALID_ARG;

    if ((size_t)frame->payload_len > SPROTOCOL_MAX_PAYLOAD_LEN)
        return SPROTOCOL_ERR_INVALID_ARG;

    if (frame->payload_len > 0)
        memcpy(frame->payload, &buf[pos], frame->payload_len);
    pos += frame->payload_len;

    uint16_t wire_crc = (uint16_t)buf[pos] | ((uint16_t)buf[pos + 1] << 8);
    uint16_t calc_crc = sprotocol_crc16(buf, pos);

    if (wire_crc != calc_crc)
        return SPROTOCOL_ERR_CRC;

    frame->crc = wire_crc;
    return SPROTOCOL_OK;
}

const char *sprotocol_get_version(void)
{
    static char ver[16];
    snprintf(ver, sizeof(ver), "%d.%d.%d",
             SPROTOCOL_VERSION_MAJOR,
             SPROTOCOL_VERSION_MINOR,
             SPROTOCOL_VERSION_PATCH);
    return ver;
}
