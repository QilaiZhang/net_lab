#include "icmp.h"
#include "ip.h"
#include <string.h>
#include <stdio.h>

icmp_entry_t icmp_table[ICMP_MAX_ENTRY];

/**
 * @brief 处理一个收到的数据包
 *        你首先要检查ICMP报头长度是否小于icmp头部长度
 *        接着，查看该报文的ICMP类型是否为回显请求，
 *        如果是，则回送一个回显应答（ping应答），需要自行封装应答包。
 * 
 *        应答包封装如下：
 *        首先调用buf_init()函数初始化txbuf，然后封装报头和数据，
 *        数据部分可以拷贝来自接收到的回显请求报文中的数据。
 *        最后将封装好的ICMP报文发送到IP层。  
 * 
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip)
{
    // TODO
    if(buf->len < sizeof(icmp_hdr_t)){
        return;
    }
    icmp_hdr_t icmp_head = *(icmp_hdr_t *)buf->data;
    uint16_t seq = icmp_head.seq;
    buf_remove_header(buf, sizeof(icmp_hdr_t));

    if(icmp_head.type == ICMP_TYPE_ECHO_REQUEST){
        buf_init(&txbuf, buf->len);
        memcpy(txbuf.data, buf->data, buf->len);
        buf_add_header(&txbuf, sizeof(icmp_hdr_t));
        icmp_hdr_t * hdr = (icmp_hdr_t *)txbuf.data;
        memset(hdr, 0, sizeof(icmp_hdr_t));
        hdr->type = ICMP_TYPE_ECHO_REPLY;
        hdr->code = 0;
        hdr->seq = seq;
        hdr->id = swap16(1);
        hdr->checksum  = checksum16((uint16_t *)hdr, txbuf.len);
        ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
    }

    if(icmp_head.type == ICMP_TYPE_ECHO_REPLY){
        seq = swap16(seq);
        if(seq < ICMP_MAX_ENTRY && icmp_table[seq].state == ICMP_WAITING){
            icmp_table[seq].recv_time = getCurrentTime();
            icmp_table[seq].state = ICMP_VALID;
            printf("来自 %s 的回复: 字节=%d 时间=%ldms \n", iptos(src_ip), buf->len, 
                (icmp_table[seq].recv_time - icmp_table[seq].send_time));
        }
    }

}

/**
 * @brief 发送icmp不可达
 *        你需要首先调用buf_init初始化buf，长度为ICMP头部 + IP头部 + 原始IP数据报中的前8字节 
 *        填写ICMP报头首部，类型值为目的不可达
 *        填写校验和
 *        将封装好的ICMP数据报发送到IP层。
 * 
 * @param recv_buf 收到的ip数据包
 * @param src_ip 源ip地址
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code)
{
    // TODO
    buf_init(&txbuf, sizeof(ip_hdr_t) + 8);
    memcpy(txbuf.data, recv_buf->data, sizeof(ip_hdr_t) + 8);

    buf_add_header(&txbuf, sizeof(icmp_hdr_t));
    memset(txbuf.data, 0, sizeof(icmp_hdr_t));
    icmp_hdr_t *icmp_head = (icmp_hdr_t *)txbuf.data;
    icmp_head->type = ICMP_TYPE_UNREACH;
    icmp_head->code = code;
    icmp_head->checksum = checksum16((uint16_t *)icmp_head, txbuf.len);
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

static int seq = 0;
/**
 * @brief 发送icmp请求
 * 
 * @param dst_ip 目的ip地址
 */
void icmp_request(uint8_t *dst_ip){
    buf_init(&txbuf, 32);
    for(int i = 0; i < 23; i++){
        txbuf.data[i] = i + 0x61;
    }
    for(int i = 0; i < 9; i++){
        txbuf.data[i+23] = i + 0x61;
    }
    buf_add_header(&txbuf, sizeof(icmp_hdr_t));
    memset(txbuf.data, 0, sizeof(icmp_hdr_t));
    icmp_hdr_t *icmp_head = (icmp_hdr_t *)txbuf.data;
    icmp_head->type = ICMP_TYPE_ECHO_REQUEST;
    icmp_head->seq = swap16(seq);
    icmp_head->checksum = checksum16((uint16_t *)icmp_head, txbuf.len);
    ip_out(&txbuf, dst_ip, NET_PROTOCOL_ICMP);
    icmp_table[seq].send_time = getCurrentTime();
    icmp_table[seq].state = ICMP_WAITING;
    seq = (seq+1) % ICMP_MAX_ENTRY;
}

void icmp_init(){
    for(int i = 0; i < ICMP_MAX_ENTRY; i++){
        icmp_table[seq].state = ICMP_INVALID;
    }
}

void icmp_update(){
    for(int i = 0; i < ICMP_MAX_ENTRY; i++){
        if(icmp_table[i].state == ICMP_TIMEOUT && getCurrentTime() > icmp_table[i].send_time + ICMP_TIMEOUT_MS){
            icmp_table[i].state = ICMP_INVALID;
        }
    }
}

void ping(uint8_t *dst_ip){
    int cnt = 4;
    time_t past = time(0);
    printf("正在 Ping %s 具有 32 字节的数据:\n", iptos(dst_ip));
    icmp_request(dst_ip);
    cnt--;
    while(cnt > 0){
        while(time(0) - past < ICMP_INTERVEL){
            net_poll();
            icmp_update();
        }
        icmp_request(dst_ip);
        past = time(0);
        cnt--;
    }
    while(time(0) - past < 1.5 * ICMP_INTERVEL){
        net_poll();
        icmp_update();
    }
    int max=0, min=1000, total = 0, recv = 0;
    for(int i = 0; i < ICMP_MAX_ENTRY; i++){
        if(icmp_table[i].state == ICMP_VALID){
            recv++;
            long interval = icmp_table[i].recv_time - icmp_table[i].send_time;
            total += interval;
            if(interval > max){
                max = interval;
            }
            if(interval < min){
                min = interval;
            }
        }else if(icmp_table[i].state == ICMP_TIMEOUT){
            icmp_table[i].state == ICMP_INVALID;
        }
    }
    int loss = 4 - recv;
    int loss_rate = (loss / 4.0) * 100;
    int aver = total / 4;
    printf("\n%s 的 Ping 统计信息:\n", iptos(dst_ip));
    printf("    数据包: 已发送 = 4，已接收 = %d，丢失 = %d (%d%% 丢失)\n", recv, loss, loss_rate);
    printf("往返行程的估计时间(以毫秒为单位):\n");
    printf("    最短 = %dms，最长 = %dms，平均 = %dms\n",min, max, aver);

}