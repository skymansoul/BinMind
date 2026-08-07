/* CVE-2016-10158 PHP EXIF get_efi_data: 固定32字节缓冲, memcpy 256字节.
 * 触发: 固定 32 字节堆缓冲, 将 256 字节输入 memcpy 写入.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void trigger(char *payload) {
    char *buf = (char *)malloc(32);
    if (!buf) return;
    memcpy(buf, payload, 256);
    printf("buf[0]=%c\n", buf[0]);
    free(buf);
}

int main(int argc, char **argv) {
    static char payload[256 + 16];
    memset(payload, 'A', sizeof(payload));
    printf("cve_2016_10158_php_exif start\n");
    trigger(payload);
    return 0;
}
