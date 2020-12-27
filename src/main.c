#include <stdio.h>
#include <string.h>
#include <time.h>
#include "net.h"
#include "icmp.h"


int main(int argc, char const *argv[])
{

    uint8_t dst_ip[4] = {192, 168, 56, 1};
    uint8_t baidu_ip[4] = {183,232,231,172};
    net_init();               //初始化协议栈

    ping(baidu_ip);

    return 0;
}
