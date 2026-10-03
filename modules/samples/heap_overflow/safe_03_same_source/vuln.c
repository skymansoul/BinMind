/*
 * 安全对照样本 C — 同源污点抑制 (TN)
 * 目标: 验证分配/写同源污点证据能抑制误报
 * malloc(n) + memcpy(..., n): n 同源, 无缩放差异 → 安全
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *clone_buffer(const char *src, size_t n) {
    char *dst = (char *)malloc(n);        /* 分配 = n */
    if (!dst) return NULL;
    memcpy(dst, src, n);                  /* 写 = n, 同源 */
    return dst;
}

int main(int argc, char **argv) {
    char src[32];
    memset(src, 'Z', 32);
    char *d = clone_buffer(src, 32);      /* 等大复制 */
    if (d) free(d);
    return 0;
}
