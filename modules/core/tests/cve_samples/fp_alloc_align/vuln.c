/*
 * 误报样本-分配器对齐 — malloc(5) + memcpy(16): glibc usable=16, 恰好安全
 * 这种模式在静态工具中经常被误报为溢出
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void small_alloc_align(const char *src) {
    char *buf = (char *)malloc(5);
    /*
     * glibc x86_64: usable_size(5) = max(32, (5+16+15)&~15) - 16 = 32 - 16 = 16
     * memcpy(16) 恰好等于可用大小 → 不会溢出
     */
    if (!buf) return;
    memcpy(buf, src, 16);
    printf("%.16s\n", buf);
    free(buf);
}

int main(void) {
    char src[16];
    memset(src, 'A', sizeof(src));
    small_alloc_align(src);
    return 0;
}
