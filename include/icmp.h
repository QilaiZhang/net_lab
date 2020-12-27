#ifndef ICMP_H
#define ICMP_H
#include <stdint.h>
#include <time.h>
#include "utils.h"
#pragma pack(1)
typedef struct icmp_hdr
{
    uint8_t type;      // 类型
    uint8_t code;      // 代码
    uint16_t checksum; // ICMP报文的校验和
    uint16_t id;       // 标识符
    uint16_t seq;      // 序号
} icmp_hdr_t;

#pragma pack()
typedef enum icmp_type
{
    ICMP_TYPE_ECHO_REQUEST = 8, // 回显请求
    ICMP_TYPE_ECHO_REPLY = 0,   // 回显响应
    ICMP_TYPE_UNREACH = 3,      // 目的不可达
} icmp_type_t;

typedef enum icmp_code
{
    ICMP_CODE_PROTOCOL_UNREACH = 2, // 协议不可达
    ICMP_CODE_PORT_UNREACH = 3      // 端口不可达
} icmp_code_t;

typedef enum icmp_state
{
    ICMP_VALID,   //有效
    ICMP_INVALID, //无效
    ICMP_TIMEOUT, //超时
    ICMP_WAITING,
} icmp_state_t;

typedef struct icmp_entry
{
    icmp_state_t state;        //状态
    long send_time;          //发送时间戳
    long recv_time;          //接收时间戳
} icmp_entry_t;

#define ICMP_MAX_ENTRY 4
#define ICMP_TIMEOUT_MS 1000
#define ICMP_INTERVEL 1

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip);

/**
 * @brief 发送icmp不可达
 * 
 * @param recv_buf 收到的ip数据包
 * @param src_ip 源ip地址
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code);

/**
 * @brief 发送icmp请求
 * 
 * @param dst_ip 目的ip地址
 */
void icmp_request(uint8_t *dst_ip);


/**
 * @brief 初始化icmp协议
 * 
 */
void icmp_init();


/**
 * @brief 更新icmp表
 * 
 */
void icmp_update();


void ping(uint8_t *dst_ip);
#endif
