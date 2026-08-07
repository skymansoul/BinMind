/*
 * 安全样本 — malloc(512) + memcpy(256): alloc >> write, 且有边界检查
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void safe_with_bounds(const char *src, size_t src_len) {
    size_t alloc = 512;
    char *buf = (char *)malloc(alloc);
    if (!buf) return;

    /* 安全: 边界检查 */
    size_t copy_sz = src_len > 256 ? 256 : src_len;
    memcpy(buf, src, copy_sz);
    printf("%s\n", buf);
    free(buf);
}

int main(void) {
    char s[256];
    memset(s, 'S', sizeof(s));
    s[255] = '\0';
    safe_with_bounds(s, 256);
    return 0;
}
