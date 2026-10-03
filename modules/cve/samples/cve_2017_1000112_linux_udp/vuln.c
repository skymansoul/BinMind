/* CVE-2017-1000112 Linux UDP fraglist: 128字节skb, UDP分片长度 memcpy 4096字节.
 * 触发: 固定 128 字节堆缓冲, 将 4096 字节输入 memcpy 写入.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void trigger(char *payload) {
    char *buf = (char *)malloc(128);
    if (!buf) return;
    memcpy(buf, payload, 4096);
    printf("buf[0]=%c\n", buf[0]);
    free(buf);
}

int main(int argc, char **argv) {
    static char payload[4096 + 16];
    memset(payload, 'A', sizeof(payload));
    printf("cve_2017_1000112_linux_udp start\n");
    trigger(payload);
    return 0;
}
