// uaf01_basic_deref_write — 基本UAF写入
// CVE参考: CVE-UAF-DEREF-WRITE, 模式: uaf_deref_write
// 检测目标: 线形扫描器能否追踪malloc→free→写入的生命周期?
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char *buf = (char *)malloc(128);
    if (!buf) return 1;
    memset(buf, 0, 128);
    free(buf);
    // UAF: 释放后写入
    memset(buf, 'X', 64);
    printf("UAF write: buf=%p\n", (void *)buf);
    return 0;
}
