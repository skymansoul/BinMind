/*
 * 安全样本2 — malloc(256) + memcpy(256): alloc == write, 恰好填满
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void exact_fit(const char *src) {
    char *buf = (char *)malloc(256);
    if (!buf) return;
    memcpy(buf, src, 256);  /* 正常: alloc == write */
    printf("%s\n", buf);
    free(buf);
}

int main(void) {
    char src[256];
    memset(src, 'E', sizeof(src));
    src[255] = '\0';
    exact_fit(src);
    return 0;
}
