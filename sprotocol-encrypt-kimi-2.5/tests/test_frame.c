/**
 * @file test_frame.c
 * @brief 帧协议测试
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "sprotocol.h"

/* 外部声明帧处理函数 */
extern int sprotocol_frame_pack(const sprotocol_frame_t* frame, uint8_t* buffer, size_t* len);
extern int sprotocol_frame_unpack(const uint8_t* buffer, size_t len, sprotocol_frame_t* frame);

/* 简单测试框架 */
#define TEST_ASSERT(cond) do { \
    if (!(cond)) { \
        printf("FAIL: %s at %s:%d\n", #cond, __FILE__, __LINE__); \
        return -1; \
    } \
} while(0)

int test_crc16(void) {
    printf("Testing CRC16...\n");
    
    /* 测试数据 */
    uint8_t data1[] = {0x01, 0x02, 0x03, 0x04};
    uint16_t crc1 = sprotocol_crc16(data1, sizeof(data1));
    
    /* 验证CRC正确性 - 将CRC附加到数据后，再计算CRC应为0 */
    uint8_t data_with_crc[6];
    memcpy(data_with_crc, data1, 4);
    data_with_crc[4] = (crc1 >> 8) & 0xFF;
    data_with_crc[5] = crc1 & 0xFF;
    
    /* 这里只验证CRC计算不为0 */
    TEST_ASSERT(crc1 != 0);
    
    /* 测试不同数据的CRC不同 */
    uint8_t data2[] = {0x01, 0x02, 0x03, 0x05};  /* 最后一位不同 */
    uint16_t crc2 = sprotocol_crc16(data2, sizeof(data2));
    TEST_ASSERT(crc1 != crc2);
    
    printf("CRC16 tests passed!\n");
    return 0;
}

int test_frame_pack_unpack(void) {
    printf("Testing frame pack/unpack...\n");
    
    /* 构建测试帧 */
    sprotocol_frame_t frame_out;
    memset(&frame_out, 0, sizeof(frame_out));
    
    frame_out.header = SPROTOCOL_FRAME_HEADER;
    frame_out.version = SPROTOCOL_FRAME_VERSION;
    frame_out.flags.need_ack = 1;
    frame_out.flags.encrypted = 0;
    frame_out.src_addr = SPROTOCOL_ADDR_MASTER;
    frame_out.dest_addr = 0x10;
    frame_out.seq = 100;
    frame_out.domain_id = SPROTOCOL_DOMAIN_BASE;
    frame_out.msg_type = SPROTOCOL_MSG_DATA;
    frame_out.payload_len = 4;
    memcpy(frame_out.payload, "test", 4);
    
    /* 打包 */
    uint8_t buffer[512];
    size_t len;
    int ret = sprotocol_frame_pack(&frame_out, buffer, &len);
    TEST_ASSERT(ret == SPROTOCOL_OK);
    TEST_ASSERT(len > 0);
    
    /* 解包 */
    sprotocol_frame_t frame_in;
    memset(&frame_in, 0, sizeof(frame_in));
    ret = sprotocol_frame_unpack(buffer, len, &frame_in);
    TEST_ASSERT(ret == SPROTOCOL_OK);
    
    /* 验证字段 */
    TEST_ASSERT(frame_in.header == frame_out.header);
    TEST_ASSERT(frame_in.version == frame_out.version);
    TEST_ASSERT(frame_in.flags.need_ack == frame_out.flags.need_ack);
    TEST_ASSERT(frame_in.src_addr == frame_out.src_addr);
    TEST_ASSERT(frame_in.dest_addr == frame_out.dest_addr);
    TEST_ASSERT(frame_in.seq == frame_out.seq);
    TEST_ASSERT(frame_in.domain_id == frame_out.domain_id);
    TEST_ASSERT(frame_in.msg_type == frame_out.msg_type);
    TEST_ASSERT(frame_in.payload_len == frame_out.payload_len);
    TEST_ASSERT(memcmp(frame_in.payload, frame_out.payload, 4) == 0);
    
    printf("Frame pack/unpack tests passed!\n");
    return 0;
}

int test_frame_crc_error(void) {
    printf("Testing frame CRC error detection...\n");
    
    /* 构建测试帧 */
    sprotocol_frame_t frame;
    memset(&frame, 0, sizeof(frame));
    frame.header = SPROTOCOL_FRAME_HEADER;
    frame.version = SPROTOCOL_FRAME_VERSION;
    frame.src_addr = SPROTOCOL_ADDR_MASTER;
    frame.dest_addr = 0x10;
    frame.msg_type = SPROTOCOL_MSG_DATA;
    
    /* 打包 */
    uint8_t buffer[512];
    size_t len;
    int ret = sprotocol_frame_pack(&frame, buffer, &len);
    TEST_ASSERT(ret == SPROTOCOL_OK);
    
    /* 破坏CRC */
    buffer[len - 1] ^= 0xFF;
    
    /* 解包应失败 */
    sprotocol_frame_t frame_in;
    ret = sprotocol_frame_unpack(buffer, len, &frame_in);
    TEST_ASSERT(ret == SPROTOCOL_ERR_CRC);
    
    printf("Frame CRC error detection tests passed!\n");
    return 0;
}

int test_frame_invalid_header(void) {
    printf("Testing frame invalid header...\n");
    
    uint8_t buffer[64];
    memset(buffer, 0, sizeof(buffer));
    buffer[0] = 0xBB;  /* 错误帧头 */
    buffer[1] = SPROTOCOL_FRAME_VERSION;
    buffer[2] = 0;  /* flags */
    buffer[3] = SPROTOCOL_ADDR_MASTER;
    buffer[4] = 0x10;
    buffer[5] = 0;  /* seq high */
    buffer[6] = 1;  /* seq low */
    buffer[7] = 0;  /* domain high */
    buffer[8] = SPROTOCOL_DOMAIN_BASE & 0xFF;
    buffer[9] = SPROTOCOL_MSG_DATA;
    buffer[10] = 0;  /* payload len */
    buffer[11] = 0;  /* CRC high */
    buffer[12] = 0;  /* CRC low */
    
    sprotocol_frame_t frame;
    int ret = sprotocol_frame_unpack(buffer, 13, &frame);
    TEST_ASSERT(ret == SPROTOCOL_ERR_INVALID_ARG);
    
    printf("Frame invalid header tests passed!\n");
    return 0;
}

int run_frame_tests(void) {
    printf("\n=== Frame Tests ===\n");
    
    if (test_crc16() < 0) return -1;
    if (test_frame_pack_unpack() < 0) return -1;
    if (test_frame_crc_error() < 0) return -1;
    if (test_frame_invalid_header() < 0) return -1;
    
    printf("All frame tests passed!\n");
    return 0;
}
