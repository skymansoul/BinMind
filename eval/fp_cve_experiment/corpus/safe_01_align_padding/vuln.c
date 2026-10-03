/* 安全: malloc(20) 在 x86-64 glibc 上 usable=32,
 * 偏移24的4字节写入落在padding区, 二进制层面合法.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    char *buf = (char *)malloc(20);
    if (!buf) return 1;
    memset(buf, 0, 20);
    *(int *)(buf + 24) = 0x41424344;
    printf("%d\n", *(int *)(buf + 24));
    free(buf);
    return 0;
}
