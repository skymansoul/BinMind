/* CVE-2016-6301 NTPd receive: 48字节堆缓冲, 网络包长度 memcpy 1024字节.
 * 触发: 固定 48 字节堆缓冲, 将 1024 字节输入 memcpy 写入.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void trigger(char *payload) {
    char *buf = (char *)malloc(48);
    if (!buf) return;
    memcpy(buf, payload, 1024);
    printf("buf[0]=%c\n", buf[0]);
    free(buf);
}

int main(int argc, char **argv) {
    static char payload[1024 + 16];
    memset(payload, 'A', sizeof(payload));
    printf("cve_2016_6301_ntpd start\n");
    trigger(payload);
    return 0;
}
