/* heap_overflow_05 — memcpy 目标缓冲区不足
 * 对应 CWE-122: memcpy 第三个参数 > 目标分配
 * 编译: gcc -o vuln vuln.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void copy_data(const char *src, int len) {
    char *dst = (char *)malloc(32);
    memcpy(dst, src, len);  /* len 可能 > 32 */
    free(dst);
}

int main() {
    char data[256];
    memset(data, 'B', 256);
    copy_data(data, 256);
    return 0;
}
