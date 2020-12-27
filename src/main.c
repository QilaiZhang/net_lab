#include <stdio.h>
#include <string.h>
#include <time.h>
#include "net.h"
#include "icmp.h"


int main(int argc, char const *argv[])
{

    uint8_t dst_ip[4] = {192, 168, 56, 2};

    net_init();               //初始化协议栈

    ping(dst_ip);

    return 0;
}
