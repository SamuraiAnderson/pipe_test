/**
 * @file frame.c
 * @brief 帧协议实现：序列化、反序列化、CRC校验
 */

#include "sprotocol.h"
#include "sprotocol_internal.h"

/* CRC16-CCITT 多项式: x^16 + x^12 + x^5 + 1 (0x1021) */
#define CRC16_POLY  0x1021

uint16_t sprotocol_crc16(const uint8_t* data, size_t len) {
    uint16_t crc = 0xFFFF;
    
    for (size_t i = 0; i < len; i++) {
        crc ^= (data[i] << 8);
        for (int j = 0; j < 8; j++) {
            if (crc & 0x8000) {
                crc = (crc << 1) ^ CRC16_POLY;
            } else {
                crc <<= 1;
            }
        }
    }
    
    return crc;
}

/**
 * @brief 将帧结构序列化为字节流
 */
int sprotocol_frame_pack(const sprotocol_frame_t* frame, uint8_t* buffer, size_t* len) {
    if (!frame || !buffer || !len) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }
    
    size_t offset = 0;
    
    /* 帧头 */
    buffer[offset++] = frame->header;
    buffer[offset++] = frame->version;
    
    /* 标志位打包到一个字节 */
    uint8_t flags = 0;
    flags |= (frame->flags.broadcast << 0);
    flags |= (frame->flags.need_ack << 1);
    flags |= (frame->flags.encrypted << 2);
    flags |= (frame->flags.retransmit << 3);
    flags |= (frame->flags.fragmented << 4);
    buffer[offset++] = flags;
    
    /* 地址 */
    buffer[offset++] = frame->src_addr;
    buffer[offset++] = frame->dest_addr;
    
    /* 序列号 (大端) */
    buffer[offset++] = (frame->seq >> 8) & 0xFF;
    buffer[offset++] = frame->seq & 0xFF;
    
    /* 领域ID (大端) */
    buffer[offset++] = (frame->domain_id >> 8) & 0xFF;
    buffer[offset++] = frame->domain_id & 0xFF;
    
    /* 消息类型 */
    buffer[offset++] = frame->msg_type;
    
    /* 载荷长度 */
    buffer[offset++] = frame->payload_len;
    
    /* 载荷数据 */
    if (frame->payload_len > 0) {
        memcpy(&buffer[offset], frame->payload, frame->payload_len);
        offset += frame->payload_len;
    }
    
    /* CRC16 (先计算CRC，不包含CRC字段本身) */
    uint16_t crc = sprotocol_crc16(buffer, offset);
    buffer[offset++] = (crc >> 8) & 0xFF;
    buffer[offset++] = crc & 0xFF;
    
    *len = offset;
    return SPROTOCOL_OK;
}

/**
 * @brief 将字节流反序列化为帧结构
 */
int sprotocol_frame_unpack(const uint8_t* buffer, size_t len, sprotocol_frame_t* frame) {
    if (!buffer || !frame || len < 11) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }
    
    size_t offset = 0;
    
    /* 帧头 */
    frame->header = buffer[offset++];
    if (frame->header != SPROTOCOL_FRAME_HEADER) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }
    
    /* 版本 */
    frame->version = buffer[offset++];
    
    /* 标志位 */
    uint8_t flags = buffer[offset++];
    frame->flags.broadcast = (flags >> 0) & 0x01;
    frame->flags.need_ack = (flags >> 1) & 0x01;
    frame->flags.encrypted = (flags >> 2) & 0x01;
    frame->flags.retransmit = (flags >> 3) & 0x01;
    frame->flags.fragmented = (flags >> 4) & 0x01;
    frame->flags.reserved = (flags >> 5) & 0x07;
    
    /* 地址 */
    frame->src_addr = buffer[offset++];
    frame->dest_addr = buffer[offset++];
    
    /* 序列号 */
    frame->seq = ((uint16_t)buffer[offset] << 8) | buffer[offset + 1];
    offset += 2;
    
    /* 领域ID */
    frame->domain_id = ((uint16_t)buffer[offset] << 8) | buffer[offset + 1];
    offset += 2;
    
    /* 消息类型 */
    frame->msg_type = buffer[offset++];
    
    /* 载荷长度 */
    frame->payload_len = buffer[offset++];
    
    /* 检查长度是否足够 */
    if (len < offset + frame->payload_len + 2) {
        return SPROTOCOL_ERR_INVALID_ARG;
    }
    
    /* 载荷数据 */
    if (frame->payload_len > 0) {
        memcpy(frame->payload, &buffer[offset], frame->payload_len);
        offset += frame->payload_len;
    }
    
    /* CRC16 */
    uint16_t recv_crc = ((uint16_t)buffer[offset] << 8) | buffer[offset + 1];
    uint16_t calc_crc = sprotocol_crc16(buffer, offset);
    
    if (recv_crc != calc_crc) {
        return SPROTOCOL_ERR_CRC;
    }
    frame->crc = recv_crc;
    
    return SPROTOCOL_OK;
}
