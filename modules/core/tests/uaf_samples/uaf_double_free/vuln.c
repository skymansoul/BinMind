/*
 * UAF-DOUBLE-FREE — 双重释放
 * free(p) 两次; 第二次释放已归还的指针.
 * 触发: cleanup() 在主路径与错误路径各 free 一次.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void cleanup(char *buf, int err) {
    free(buf);
    if (err) {
        /* 漏洞: 错误路径重复释放 */
        free(buf);
    }
}

int main(void) {
    char *buf = (char *)malloc(32);
    if (!buf) return 1;
    strcpy(buf, "data");
    cleanup(buf, 1);
    return 0;
}
