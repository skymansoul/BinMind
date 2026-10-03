/*
 * UAF-DIRECT — 直接 use-after-free
 * free(buf) 后立即解引用 buf, 生命周期违规.
 * 触发: process(1) 释放后 printf 使用.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void process(int mode) {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    strcpy(buf, "hello");
    free(buf);
    /* 漏洞: 释放后解引用 */
    if (mode) {
        printf("%s\n", buf);
    }
}

int main(void) {
    process(1);
    return 0;
}
