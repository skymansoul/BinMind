/* 网络接收数据作为格式串. */
#include <stdio.h>
#include <string.h>
int main(void) {
    char buf[128];
    memcpy(buf, "user:%s", 8);
    printf(buf);
    return 0;
}
