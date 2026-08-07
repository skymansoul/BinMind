/* CVE-2017-7269 IIS ScStoragePathFromUrl: 80字节堆缓冲, 请求URL长度 memcpy 512字节.
 * 触发: 固定 80 字节堆缓冲, 将 512 字节输入 memcpy 写入.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void trigger(char *payload) {
    char *buf = (char *)malloc(80);
    if (!buf) return;
    memcpy(buf, payload, 512);
    printf("buf[0]=%c\n", buf[0]);
    free(buf);
}

int main(int argc, char **argv) {
    static char payload[512 + 16];
    memset(payload, 'A', sizeof(payload));
    printf("cve_2017_7269_iis_scstorage start\n");
    trigger(payload);
    return 0;
}
