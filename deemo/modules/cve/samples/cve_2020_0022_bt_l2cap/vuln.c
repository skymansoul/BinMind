/* CVE-2020-0022 Android Bluetooth L2CAP: 32字节堆缓冲, 畸形包长度 memcpy 128字节.
 * 触发: 固定 32 字节堆缓冲, 将 128 字节输入 memcpy 写入.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void trigger(char *payload) {
    char *buf = (char *)malloc(32);
    if (!buf) return;
    memcpy(buf, payload, 128);
    printf("buf[0]=%c\n", buf[0]);
    free(buf);
}

int main(int argc, char **argv) {
    static char payload[128 + 16];
    memset(payload, 'A', sizeof(payload));
    printf("cve_2020_0022_bt_l2cap start\n");
    trigger(payload);
    return 0;
}
