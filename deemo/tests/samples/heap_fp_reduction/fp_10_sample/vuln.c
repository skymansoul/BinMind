/*
 * FP-10: 多级指针间接访问
 *
 * buf = malloc(128); p = buf; q = p; 通过 q 写入偏移 120。
 * 别名追踪需要将 q 解析回 buf 才能正确判断边界。
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    char *buf = malloc(128);
    if (!buf) return 1;
    char *p = buf;
    char *q = p;  // 多级别名
    memset(q + 64, 'Y', 32);  // 写入 buf[64..95], 安全
    printf("alias test: q[64]=%c q[95]=%c\n", q[64], q[95]);
    free(buf);
    return 0;
}
