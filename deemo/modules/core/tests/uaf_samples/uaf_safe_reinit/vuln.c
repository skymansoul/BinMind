/*
 * UAF-SAFE-REINIT — 安全: 释放后指针重新初始化再使用
 * free(p) 后 p = malloc(新块), 后续使用合法新块.
 * 触发: process() 中重新分配后写入/读取.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void process(int mode) {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    free(buf);
    /* 安全: 重新初始化指针 */
    buf = (char *)malloc(32);
    if (!buf) return;
    strcpy(buf, "reinit-ok");
    printf("%s\n", buf);
    free(buf);
}

int main(void) {
    process(1);
    return 0;
}
