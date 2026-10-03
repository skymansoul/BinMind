/* CVE-2019-2215 Android Binder 交易: 64字节堆缓冲, 事务数据 memcpy 512字节.
 * 触发: 固定 64 字节堆缓冲, 将 512 字节输入 memcpy 写入.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void trigger(char *payload) {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    memcpy(buf, payload, 512);
    printf("buf[0]=%c\n", buf[0]);
    free(buf);
}

int main(int argc, char **argv) {
    static char payload[512 + 16];
    memset(payload, 'A', sizeof(payload));
    printf("cve_2019_2215_binder_trans start\n");
    trigger(payload);
    return 0;
}
