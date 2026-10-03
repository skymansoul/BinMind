/*
 * UAF-SAFE-NULL — 安全: 释放后置空并判空再使用
 * free(p) 后 p = NULL; if (p) 才访问.
 * 触发: cleanup() 中置空后按判空分支跳过.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void cleanup(char *buf) {
    free(buf);
    /* 安全: 置空并判空 */
    buf = NULL;
    if (buf) {
        strcpy(buf, "never");
    }
}

int main(void) {
    char *buf = (char *)malloc(32);
    if (!buf) return 1;
    strcpy(buf, "data");
    cleanup(buf);
    return 0;
}
