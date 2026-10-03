/* CVE-2019-1579 Palo Alto GlobalProtect: 16字节堆缓冲, 会话长度 memcpy 256字节.
 * 触发: 固定 16 字节堆缓冲, 将 256 字节输入 memcpy 写入.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void trigger(char *payload) {
    char *buf = (char *)malloc(16);
    if (!buf) return;
    memcpy(buf, payload, 256);
    printf("buf[0]=%c\n", buf[0]);
    free(buf);
}

int main(int argc, char **argv) {
    static char payload[256 + 16];
    memset(payload, 'A', sizeof(payload));
    printf("cve_2019_1579_paloalto_gp start\n");
    trigger(payload);
    return 0;
}
