/*
 * safe_01 packed variant — 仅剥离符号 (-s), 安全样本.
 * malloc(256) + memcpy(128): alloc >> write, 应被判定安全.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void safe_copy(const char *src) {
    char *buf = (char *)malloc(256);
    if (!buf) return;
    memcpy(buf, src, 128);
    printf("%s\n", buf);
    free(buf);
}

int main(void) {
    char s[128];
    memset(s, 'S', sizeof(s));
    s[127] = '\0';
    safe_copy(s);
    return 0;
}
