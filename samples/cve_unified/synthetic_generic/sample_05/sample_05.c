/*
 * sample_05 — realloc 后使用旧大小.
 *
 * 漏洞: realloc 缩小了缓冲区, 但后续代码仍按旧大小写入.
 *
 * CWE-122.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *buf = (char *)malloc(256);
    if (!buf) return 1;
    memset(buf, 'B', 256);

    /* realloc 缩小到 16 字节 */
    char *new_buf = (char *)realloc(buf, 16);
    if (!new_buf) { free(buf); return 1; }
    buf = new_buf;

    /* 仍按旧大小(256)写入 → 溢出240字节 */
    memset(buf, 'C', 256);

    printf("buf[0] = %c\n", buf[0]);
    free(buf);
    return 0;
}
