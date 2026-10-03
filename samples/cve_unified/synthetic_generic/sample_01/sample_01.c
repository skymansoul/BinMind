/*
 * sample_01 — 基础堆溢出: malloc + memcpy 写入超界.
 *
 * 漏洞: malloc(64) 分配64字节, memcpy 写入256字节 → 堆溢出.
 * CWE-122: Heap-based Buffer Overflow.
 *
 * 编译: gcc -o sample_01 sample_01.c
 * 触发: ./sample_01 (always overflows)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *buf = (char *)malloc(64);
    if (!buf) return 1;

    /* 漏洞: 写入256字节到64字节的缓冲区 */
    memset(buf, 'A', 256);

    printf("buf[0] = %c\n", buf[0]);
    free(buf);
    return 0;
}
