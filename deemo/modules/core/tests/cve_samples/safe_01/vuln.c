/*
 * 安全样本1 — malloc(256) + memcpy(128): alloc > write, 不溢出
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void safe_copy(const char *src) {
    char *buf = (char *)malloc(256);
    if (!buf) return;
    memcpy(buf, src, 128);  /* 正常: 256 >= 128 */
    printf("%s\n", buf);
    free(buf);
}

int main(void) {
    char src[128];
    memset(src, 'S', sizeof(src));
    src[127] = '\0';
    safe_copy(src);
    return 0;
}
