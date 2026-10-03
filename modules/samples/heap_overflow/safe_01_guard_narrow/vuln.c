/*
 * 安全对照样本 A — 路径守卫收窄 (TN)
 * 目标: 验证守卫窄化证据能抑制误报
 * malloc(64) + memcpy(<=32) 有显式上界守卫
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *safe_copy(const char *src, size_t len) {
    if (len > 32) return NULL;            /* 守卫: len <= 32 */
    char *dst = (char *)malloc(64);
    if (!dst) return NULL;
    memcpy(dst, src, len);                /* <= 32 < 64 安全 */
    return dst;
}

int main(int argc, char **argv) {
    char src[32];
    memset(src, 'X', 32);
    char *d = safe_copy(src, 16);         /* 触发守卫路径 */
    if (d) free(d);
    return 0;
}
