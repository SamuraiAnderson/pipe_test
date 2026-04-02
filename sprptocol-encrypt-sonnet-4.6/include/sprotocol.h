/**
 * @file sprotocol.h
 * @brief 面向嵌入式设备的无线通信协议库
 * 
 * 核心功能：
 * - 主从架构通信
 * - 设备配对管理
 * - 消息帧协议
 * - 领域架构
 * - 设备状态管理
 * - ECC 加密通信
 * 
 */

#ifndef SPROTOCOL_H
#define SPROTOCOL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * 常量定义
 *============================================================================*/

#define SPROTOCOL_VERSION_MAJOR     1
#define SPROTOCOL_VERSION_MINOR     0
#define SPROTOCOL_VERSION_PATCH     0

#define SPROTOCOL_MAX_SLAVES        5       /**< 最大从机数量 */
#define SPROTOCOL_MIN_SLAVE_ADDR    0x10    /**< 最小从机地址 */
#define SPROTOCOL_MAX_SLAVE_ADDR    0x14    /**< 最大从机地址 (0x10 + 5 - 1) */

#define SPROTOCOL_ADDR_BROADCAST    0xFF    /**< 广播地址 */
#define SPROTOCOL_ADDR_MASTER       0x00    /**< 主机地址 */

#define SPROTOCOL_FRAME_HEADER      0xAA    /**< 帧头 */
#define SPROTOCOL_FRAME_VERSION     0x01    /**< 协议版本 */

#define SPROTOCOL_MAX_PAYLOAD_LEN   256     /**< 最大载荷长度 */

/* 领域 ID 定义 */
#define SPROTOCOL_DOMAIN_BASE       10000   /**< 基础领域 */
#define SPROTOCOL_DOMAIN_OTA        10001   /**< OTA 领域 */

/* 消息类型 */
#define SPROTOCOL_MSG_PAIR_REQ      0x01    /**< 配对请求 */
#define SPROTOCOL_MSG_PAIR_RSP      0x02    /**< 配对响应 */
#define SPROTOCOL_MSG_PAIR_CFM      0x03    /**< 配对确认 */
#define SPROTOCOL_MSG_DATA          0x10    /**< 数据消息 */
#define SPROTOCOL_MSG_HEARTBEAT     0x20    /**< 心跳消息 */
#define SPROTOCOL_MSG_ACK           0x30    /**< 确认消息 */
#define SPROTOCOL_MSG_NACK          0x31    /**< 否认消息 */

/* 配对状态 */
#define SPROTOCOL_PAIR_NONE         0
#define SPROTOCOL_PAIR_PENDING      1
#define SPROTOCOL_PAIR_COMPLETE     2

/* 设备在线状态 */
#define SPROTOCOL_DEVICE_OFFLINE    0
#define SPROTOCOL_DEVICE_ONLINE     1

/* 错误码 */
#define SPROTOCOL_OK                0
#define SPROTOCOL_ERR_INVALID_ARG   -1
#define SPROTOCOL_ERR_NO_MEMORY     -2
#define SPROTOCOL_ERR_BUSY          -3
#define SPROTOCOL_ERR_TIMEOUT       -4
#define SPROTOCOL_ERR_NOT_FOUND     -5
#define SPROTOCOL_ERR_FULL          -6
#define SPROTOCOL_ERR_INVALID_STATE -7
#define SPROTOCOL_ERR_CRC           -8
#define SPROTOCOL_ERR_SEQ           -9
#define SPROTOCOL_ERR_BLACKLIST     -10
#define SPROTOCOL_ERR_CRYPTO        -11   /**< 加密错误 */

/* 加密类型 */
#define SPROTOCOL_ENC_NONE          0
#define SPROTOCOL_ENC_ECC           1     /**< ECC 椭圆曲线加密 */

/*============================================================================
 * 类型定义
 *============================================================================*/

/**
 * @brief 设备角色
 */
typedef enum {
    SPROTOCOL_ROLE_SLAVE = 0,
    SPROTOCOL_ROLE_MASTER = 1
} sprotocol_role_t;

/**
 * @brief 帧标志位
 */
typedef struct {
    uint8_t broadcast : 1;    /**< 广播标志 */
    uint8_t need_ack : 1;     /**< 需要 ACK */
    uint8_t encrypted : 1;    /**< 加密标志（保留） */
    uint8_t retransmit : 1;   /**< 重传标志 */
    uint8_t fragmented : 1;   /**< 分包标志 */
    uint8_t reserved : 3;     /**< 保留位 */
} sprotocol_flags_t;

/**
 * @brief 协议帧结构
 */
typedef struct {
    uint8_t  header;          /**< 帧头 0xAA */
    uint8_t  version;         /**< 协议版本 */
    sprotocol_flags_t flags;  /**< 标志位 */
    uint8_t  src_addr;        /**< 源地址 */
    uint8_t  dest_addr;       /**< 目的地址 */
    uint16_t seq;             /**< 序列号 */
    uint16_t domain_id;       /**< 领域 ID */
    uint8_t  msg_type;        /**< 消息类型 */
    uint8_t  payload_len;     /**< 载荷长度 */
    uint8_t  payload[SPROTOCOL_MAX_PAYLOAD_LEN]; /**< 载荷数据 */
    uint16_t crc;             /**< CRC 校验 */
} sprotocol_frame_t;

/**
 * @brief 设备信息
 */
typedef struct {
    uint8_t  addr;            /**< 设备地址 */
    uint8_t  pair_status;     /**< 配对状态 */
    uint8_t  online;          /**< 在线状态 */
    uint16_t seq_tx;          /**< 发送序列号 */
    uint16_t seq_rx;          /**< 接收序列号 */
    uint32_t last_heartbeat;  /**< 最后心跳时间 (ms) */
    uint32_t pair_time;       /**< 配对时间 (ms) */
} sprotocol_device_t;

/**
 * @brief 黑名单条目
 */
typedef struct {
    uint8_t  addr;            /**< 设备地址 */
    uint32_t add_time;        /**< 加入时间 (ms) */
    uint32_t expire_time;     /**< 过期时间 (ms) */
    uint8_t  trigger_count;   /**< 触发次数 */
} sprotocol_blacklist_entry_t;

#define SPROTOCOL_MAX_BLACKLIST   10      /**< 最大黑名单数量 */
#define SPROTOCOL_BLACKLIST_WINDOW 3600000 /**< 窗口期 1 小时 (ms) */
#define SPROTOCOL_BLACKLIST_LIMIT  20      /**< 触发次数限制 */
#define SPROTOCOL_BLACKLIST_EXPIRE 86400000 /**< 过期时间 24 小时 (ms) */

/**
 * @brief 发送回调函数类型
 */
typedef void (*sprotocol_send_cb)(const uint8_t* data, size_t len, void* user_data);

/**
 * @brief 配对状态变化回调
 */
typedef void (*sprotocol_pair_cb)(uint8_t addr, uint8_t status, void* user_data);

/**
 * @brief 在线状态变化回调
 */
typedef void (*sprotocol_online_cb)(uint8_t addr, uint8_t online, void* user_data);

/**
 * @brief 消息接收回调
 */
typedef void (*sprotocol_recv_cb)(uint8_t src_addr, uint16_t domain_id,
                                   uint8_t msg_type, const uint8_t* payload,
                                   size_t len, void* user_data);

/**
 * @brief Flash 读回调
 */
typedef int (*sprotocol_flash_read_cb)(uint32_t addr, uint8_t* data, size_t len, void* user_data);

/**
 * @brief Flash 写回调
 */
typedef int (*sprotocol_flash_write_cb)(uint32_t addr, const uint8_t* data, size_t len, void* user_data);

/**
 * @brief 获取系统时间回调 (ms)
 */
typedef uint32_t (*sprotocol_time_cb)(void);

/**
 * @brief 协议配置结构
 */
typedef struct {
    sprotocol_role_t role;              /**< 设备角色 */
    uint8_t local_addr;                 /**< 本地地址 */
    uint8_t max_slaves;                 /**< 最大从机数量 (1-5) */
    uint32_t heartbeat_timeout;         /**< 心跳超时时间 (ms) */
    uint32_t pair_timeout;              /**< 配对超时时间 (ms) */
    uint16_t seq_save_interval;         /**< 序列号保存间隔 (ms) */
    uint16_t seq_check_interval;        /**< 序列号检查间隔 (ms) */
    
    /* 加密配置 */
    uint8_t encryption_enabled;         /**< 是否启用加密 (0:禁用，1:启用) */
    uint8_t enc_type;                   /**< 加密类型 (SPROTOCOL_ENC_NONE/SProTOCOL_ENC_ECC) */
    
    /* 回调函数 */
    sprotocol_send_cb send_cb;          /**< 发送回调 */
    sprotocol_pair_cb pair_cb;          /**< 配对状态变化回调 */
    sprotocol_online_cb online_cb;      /**< 在线状态变化回调 */
    sprotocol_recv_cb recv_cb;          /**< 消息接收回调 */
    sprotocol_flash_read_cb flash_read; /**< Flash 读回调 */
    sprotocol_flash_write_cb flash_write; /**< Flash 写回调 */
    sprotocol_time_cb get_time;         /**< 获取时间回调 */
    
    void* user_data;                    /**< 用户数据 */
} sprotocol_config_t;

/**
 * @brief 协议句柄
 */
typedef struct sprotocol_handle* sprotocol_handle_t;

/*============================================================================
 * 核心 API
 *============================================================================*/

/**
 * @brief 初始化协议栈
 * @param config 配置参数
 * @return 协议句柄，失败返回 NULL
 */
sprotocol_handle_t sprotocol_init(const sprotocol_config_t* config);

/**
 * @brief 反初始化协议栈
 * @param handle 协议句柄
 */
void sprotocol_deinit(sprotocol_handle_t handle);

/**
 * @brief 协议栈周期处理函数（需在主循环调用）
 * @param handle 协议句柄
 */
void sprotocol_poll(sprotocol_handle_t handle);

/**
 * @brief 接收数据输入
 * @param handle 协议句柄
 * @param data 接收到的数据
 * @param len 数据长度
 */
void sprotocol_input(sprotocol_handle_t handle, const uint8_t* data, size_t len);

/*============================================================================
 * 配对管理 API
 *============================================================================*/

/**
 * @brief 发起配对请求（主机调用）
 * @param handle 协议句柄
 * @param slave_addr 从机地址
 * @return SPROTOCOL_OK 成功，其他为错误码
 * 
 * @note 从机收到配对请求后会自动响应，无需应用层干预。
 *       配对流程：PAIR_REQ → PAIR_RSP → PAIR_CFM
 */
int sprotocol_pair_request(sprotocol_handle_t handle, uint8_t slave_addr);

/**
 * @brief 删除配对设备
 * @param handle 协议句柄
 * @param addr 设备地址
 * @return SPROTOCOL_OK 成功，其他为错误码
 */
int sprotocol_remove_device(sprotocol_handle_t handle, uint8_t addr);

/**
 * @brief 删除所有配对设备
 * @param handle 协议句柄
 */
void sprotocol_remove_all_devices(sprotocol_handle_t handle);

/**
 * @brief 获取配对设备列表
 * @param handle 协议句柄
 * @param addrs 地址数组输出
 * @param max_count 最大数量
 * @return 实际设备数量
 */
int sprotocol_get_paired_devices(sprotocol_handle_t handle, uint8_t* addrs, uint8_t max_count);

/**
 * @brief 获取设备信息
 * @param handle 协议句柄
 * @param addr 设备地址
 * @return 设备信息指针，不存在返回 NULL
 */
const sprotocol_device_t* sprotocol_get_device(sprotocol_handle_t handle, uint8_t addr);

/*============================================================================
 * 数据通信 API
 *============================================================================*/

/**
 * @brief 发送数据
 * @param handle 协议句柄
 * @param dest_addr 目的地址
 * @param domain_id 领域 ID
 * @param msg_type 消息类型
 * @param payload 载荷数据
 * @param len 载荷长度
 * @return SPROTOCOL_OK 成功，其他为错误码
 */
int sprotocol_send(sprotocol_handle_t handle, uint8_t dest_addr, uint16_t domain_id,
                   uint8_t msg_type, const uint8_t* payload, size_t len);

/**
 * @brief 发送广播
 * @param handle 协议句柄
 * @param domain_id 领域 ID
 * @param msg_type 消息类型
 * @param payload 载荷数据
 * @param len 载荷长度
 * @return SPROTOCOL_OK 成功，其他为错误码
 */
int sprotocol_broadcast(sprotocol_handle_t handle, uint16_t domain_id,
                        uint8_t msg_type, const uint8_t* payload, size_t len);

/*============================================================================
 * 心跳 API
 *============================================================================*/

/**
 * @brief 发送心跳（从机调用）
 * @param handle 协议句柄
 * @return SPROTOCOL_OK 成功，其他为错误码
 */
int sprotocol_send_heartbeat(sprotocol_handle_t handle);

/**
 * @brief 检查设备是否在线
 * @param handle 协议句柄
 * @param addr 设备地址
 * @return 1 在线，0 离线
 */
int sprotocol_is_device_online(sprotocol_handle_t handle, uint8_t addr);

/*============================================================================
 * 序列号 API
 *============================================================================*/

/**
 * @brief 获取设备的发送序列号
 * @param handle 协议句柄
 * @param addr 设备地址
 * @return 序列号
 */
uint16_t sprotocol_get_tx_seq(sprotocol_handle_t handle, uint8_t addr);

/**
 * @brief 设置序列号保存间隔
 * @param handle 协议句柄
 * @param interval_ms 间隔时间 (ms)
 */
void sprotocol_set_seq_save_interval(sprotocol_handle_t handle, uint16_t interval_ms);

/*============================================================================
 * 黑名单 API
 *============================================================================*/

/**
 * @brief 检查地址是否在黑名单中
 * @param handle 协议句柄
 * @param addr 设备地址
 * @return 1 在黑名单中，0 不在
 */
int sprotocol_is_blacklisted(sprotocol_handle_t handle, uint8_t addr);

/**
 * @brief 获取黑名单数量
 * @param handle 协议句柄
 * @return 黑名单数量
 */
int sprotocol_get_blacklist_count(sprotocol_handle_t handle);

/*============================================================================
 * 工具函数
 *============================================================================*/

/**
 * @brief 计算 CRC16
 * @param data 数据
 * @param len 数据长度
 * @return CRC 值
 */
uint16_t sprotocol_crc16(const uint8_t* data, size_t len);

/**
 * @brief 获取协议版本字符串
 * @return 版本字符串
 */
const char* sprotocol_get_version(void);

#ifdef __cplusplus
}
#endif

#endif /* SPROTOCOL_H */