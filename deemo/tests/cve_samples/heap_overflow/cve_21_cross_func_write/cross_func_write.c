/*
 * CVE-21: 跨函数写入溢出 — alloc在funcA, 危险memcpy在funcB
 *
 * 模式: caller分配32B, callee做memcpy(ds, src, 128) → 溢出
 * 触发: 跨函数分析必须关联alloc和write的约束
 *
 * 对应: 类似 CVE-2021-3801 (libcroco 堆溢出)
 * 检测预期: PROVEN_OVERFLOW (跨函数约束传播后)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void copy_data(char *dst, const char *src, int len) {
    memcpy(dst, src, len);
}

int main(void) {
    char *buf = (char *)malloc(32);
    if (!buf) return 1;
    char data[128];
    memset(data, 'X', sizeof(data));
    copy_data(buf, data, 128);
    printf("cross_func_write done\n");
    free(buf);
    return 0;
}
