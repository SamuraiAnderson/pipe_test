#include "sprotocol_internal.h"

static uint8_t sprotocol_pack_flags(sprotocol_flags_t flags)
{
    uint8_t value = 0;

    value |= (flags.broadcast ? 1U : 0U) << 0;
    value |= (flags.need_ack ? 1U : 0U) << 1;
    value |= (flags.encrypted ? 1U : 0U) << 2;
    value |= (flags.retransmit ? 1U : 0U) << 3;
    value |= (flags.fragmented ? 1U : 0U) << 4;
    return value;
}

static sprotocol_flags_t sprotocol_unpack_flags(uint8_t value)
{
    sprotocol_flags_t flags;

    memset(&flags, 0, sizeof(flags));
    flags.broadcast = (value >> 0) & 0x01U;
    flags.need_ack = (value >> 1) & 0x01U;
    flags.encrypted = (value >> 2) & 0x01U;
    flags.retransmit = (value >> 3) & 0x01U;
    flags.fragmented = (value >> 4) & 0x01U;
    flags.reserved = 0;
    return flags;
}

static void sprotocol_write_u16(uint8_t* out, uint16_t value)
{
    out[0] = (uint8_t)(value >> 8);
    out[1] = (uint8_t)(value & 0xFFU);
}

static uint16_t sprotocol_read_u16(const uint8_t* in)
{
    return (uint16_t)(((uint16_t)in[0] << 8) | (uint16_t)in[1]);
}

uint16_t sprotocol_crc16(const uint8_t* data, size_t len)
{
    uint16_t crc = 0xFFFFU;
    size_t i;
    uint8_t bit;

    if (data == NULL && len != 0U) {
        return 0;
    }

    for (i = 0; i < len; ++i) {
        crc ^= (uint16_t)data[i] << 8;
        for (bit = 0; bit < 8U; ++bit) {
            if ((crc & 0x8000U) != 0U) {
                crc = (uint16_t)((crc << 1) ^ 0x1021U);
            } else {
                crc <<= 1;
            }
        }
    }

    return crc;
}

int sprotocol_build_frame(const sprotocol_frame_t* frame, sprotocol_wire_frame_t* wire)
{
    size_t total_len;
    uint16_t crc;

    if (frame == NULL || wire == NULL) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }

    if ((size_t)frame->payload_len > SPROTOCOL_PAYLOAD_ENCODE_LIMIT) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }

    total_len = SPROTOCOL_WIRE_HEADER_LEN + (size_t)frame->payload_len + SPROTOCOL_WIRE_CRC_LEN;
    if (total_len > sizeof(wire->data)) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }

    wire->data[0] = frame->header;
    wire->data[1] = frame->version;
    wire->data[2] = sprotocol_pack_flags(frame->flags);
    wire->data[3] = frame->src_addr;
    wire->data[4] = frame->dest_addr;
    sprotocol_write_u16(&wire->data[5], frame->seq);
    sprotocol_write_u16(&wire->data[7], frame->domain_id);
    wire->data[9] = frame->msg_type;
    wire->data[10] = frame->payload_len;
    if (frame->payload_len > 0U) {
        memcpy(&wire->data[11], frame->payload, frame->payload_len);
    }

    crc = sprotocol_crc16(wire->data, SPROTOCOL_WIRE_HEADER_LEN + frame->payload_len);
    sprotocol_write_u16(&wire->data[SPROTOCOL_WIRE_HEADER_LEN + frame->payload_len], crc);
    wire->len = total_len;
    return SPROTOCOL_OK;
}

int sprotocol_parse_frame(const uint8_t* data, size_t len, sprotocol_frame_t* frame)
{
    size_t payload_len;
    uint16_t actual_crc;
    uint16_t expected_crc;

    if (data == NULL || frame == NULL) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }

    if (len < (SPROTOCOL_WIRE_HEADER_LEN + SPROTOCOL_WIRE_CRC_LEN)) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }

    if (data[0] != SPROTOCOL_FRAME_HEADER || data[1] != SPROTOCOL_FRAME_VERSION) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }

    payload_len = data[10];
    if (payload_len > SPROTOCOL_MAX_PAYLOAD_LEN) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }

    if (len != (SPROTOCOL_WIRE_HEADER_LEN + payload_len + SPROTOCOL_WIRE_CRC_LEN)) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }

    expected_crc = sprotocol_read_u16(&data[SPROTOCOL_WIRE_HEADER_LEN + payload_len]);
    actual_crc = sprotocol_crc16(data, SPROTOCOL_WIRE_HEADER_LEN + payload_len);
    if (expected_crc != actual_crc) {
        return SPROTOCOL_ERR_CRC;
    }

    memset(frame, 0, sizeof(*frame));
    frame->header = data[0];
    frame->version = data[1];
    frame->flags = sprotocol_unpack_flags(data[2]);
    frame->src_addr = data[3];
    frame->dest_addr = data[4];
    frame->seq = sprotocol_read_u16(&data[5]);
    frame->domain_id = sprotocol_read_u16(&data[7]);
    frame->msg_type = data[9];
    frame->payload_len = data[10];
    if (payload_len > 0U) {
        memcpy(frame->payload, &data[11], payload_len);
    }
    frame->crc = expected_crc;
    return SPROTOCOL_OK;
}
