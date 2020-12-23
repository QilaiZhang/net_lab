#include "ip.h"
#include "arp.h"
#include "icmp.h"
#include "udp.h"
#include <string.h>
#include <stdio.h>
#include "ethernet.h"

/**
 * @brief 处理一个收到的数据包
 *        你首先需要做报头检查，检查项包括：版本号、总长度、首部长度等。
 * 
 *        接着，计算头部校验和，注意：需要先把头部校验和字段缓存起来，再将校验和字段清零，
 *        调用checksum16()函数计算头部检验和，比较计算的结果与之前缓存的校验和是否一致，
 *        如果不一致，则不处理该数据报。
 * 
 *        检查收到的数据包的目的IP地址是否为本机的IP地址，只处理目的IP为本机的数据报。
 * 
 *        检查IP报头的协议字段：
 *        如果是ICMP协议，则去掉IP头部，发送给ICMP协议层处理
 *        如果是UDP协议，则去掉IP头部，发送给UDP协议层处理
 *        如果是本实验中不支持的其他协议，则需要调用icmp_unreachable()函数回送一个ICMP协议不可达的报文。
 *          
 * @param buf 要处理的包
 */

#define PACKET_SIZE (ETHERNET_MTU - sizeof(ip_hdr_t))

void ip_in(buf_t *buf)
{
    // 报头检查
    ip_hdr_t ip_head;
    ip_head.version = *(uint8_t *)buf->data >> 4;
    if(ip_head.version != IP_VERSION_4){
        return;
    }
    ip_head.hdr_len = *(uint8_t *)buf->data & 0x0f;
    if(ip_head.hdr_len < 5){
        return;
    }
    ip_head.total_len = swap16(*((uint16_t *)buf->data + 1));
    if(ip_head.total_len < 20){
        return;
    }

    // 计算头部校验和
    ip_head.hdr_checksum = *((uint16_t *)buf->data + 5);
    *((uint16_t *)buf->data + 5) = 0;
    if( checksum16((uint16_t *)buf->data, ip_head.hdr_len * IP_HDR_LEN_PER_BYTE) != ip_head.hdr_checksum){
        return;
    }

    // 检查IP地址
    uint8_t *p = buf->data + 12;
    if(memcmp(p + 4, net_if_ip, NET_IP_LEN) != 0){
        return;
    }
    memcpy(ip_head.src_ip, p, NET_IP_LEN);
    memcpy(ip_head.dest_ip, p + 4, NET_IP_LEN);

    // 检查协议
    ip_head.protocol = *(buf->data + 9);

    switch(ip_head.protocol){
        case(NET_PROTOCOL_ICMP):
            buf_remove_header(buf, IP_HDR_LEN_PER_BYTE * ip_head.hdr_len);
            icmp_in(buf, ip_head.src_ip);
            break;
        case(NET_PROTOCOL_UDP):
            buf_remove_header(buf, IP_HDR_LEN_PER_BYTE * ip_head.hdr_len);
            udp_in(buf, ip_head.src_ip);
            break;
        default:
            *((uint16_t *)buf->data + 5) = ip_head.hdr_checksum;
            icmp_unreachable(buf, ip_head.src_ip, ICMP_CODE_PROTOCOL_UNREACH);
            break;
    }

}

/**
 * @brief 处理一个要发送的ip分片
 *        你需要调用buf_add_header增加IP数据报头部缓存空间。
 *        填写IP数据报头部字段。
 *        将checksum字段填0，再调用checksum16()函数计算校验和，并将计算后的结果填写到checksum字段中。
 *        将封装后的IP数据报发送到arp层。
 * 
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf)
{
    buf_add_header(buf, sizeof(ip_hdr_t));
    memset(buf->data, 0, sizeof(ip_hdr_t));

    *buf->data = IP_VERSION_4 << 4;
    *buf->data |= 5;
    *(uint16_t *)(buf->data + 2) = swap16(buf->len);
    *(uint16_t *)(buf->data + 4) = swap16(id);
    *(buf->data + 6) |= mf;
    *(uint16_t *)(buf->data + 6) |= swap16(offset);

    *(buf->data + 8) = IP_DEFALUT_TTL;
    *(buf->data + 9) = protocol;
    
    
    memcpy(buf->data + 12, net_if_ip, NET_IP_LEN);
    memcpy(buf->data + 16, ip, NET_IP_LEN);

    *(uint16_t *)(buf->data + 10) = checksum16((uint16_t *)buf->data, sizeof(ip_hdr_t));
    arp_out(buf, ip, NET_PROTOCOL_IP);
}

/**
 * @brief 处理一个要发送的ip数据包
 *        你首先需要检查需要发送的IP数据报是否大于以太网帧的最大包长（1500字节 - 以太网报头长度）。
 *        
 *        如果超过，则需要分片发送。 
 *        分片步骤：
 *        （1）调用buf_init()函数初始化buf，长度为以太网帧的最大包长（1500字节 - 以太网报头长度）
 *        （2）将数据报截断，每个截断后的包长度 = 以太网帧的最大包长，调用ip_fragment_out()函数发送出去
 *        （3）如果截断后最后的一个分片小于或等于以太网帧的最大包长，
 *             调用buf_init()函数初始化buf，长度为该分片大小，再调用ip_fragment_out()函数发送出去
 *             注意：id为IP数据报的分片标识，从0开始编号，每增加一个分片，自加1。最后一个分片的MF = 0
 *    
 *        如果没有超过以太网帧的最大包长，则直接调用调用ip_fragment_out()函数发送出去。
 * 
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */

static uint16_t buf_id = 0;

void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol)
{
    if(buf->len < PACKET_SIZE){
        ip_fragment_out(buf, ip, protocol, buf_id++, 0, 0);
        return;
    }

    int frag_num = buf->len / PACKET_SIZE + 1;
    uint16_t length = buf->len;
    uint8_t *base = buf->data;
    uint16_t offset = 0;

    for(int i = 0; i < frag_num; i++){
        if(i == frag_num - 1){
            buf_init(buf, length % PACKET_SIZE);
            buf->data = base + offset;
            ip_fragment_out(buf, ip, protocol, buf_id++, offset / IP_HDR_OFFSET_PER_BYTE, 0);
            return;
        }
        buf_init(buf, PACKET_SIZE);
        buf->data = base + offset;
        ip_fragment_out(buf, ip, protocol, buf_id, offset / IP_HDR_OFFSET_PER_BYTE, IP_MORE_FRAGMENT);
        offset += PACKET_SIZE;
    }    
}
