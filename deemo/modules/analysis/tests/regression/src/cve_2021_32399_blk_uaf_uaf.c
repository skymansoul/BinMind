#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// cve_2021_32399 UAF: deref pattern: malloc→free→mov rax,[global]→use
char *blk_uaf_global = NULL;

void blk_uaf_vuln() {
    char *buf = (char *)malloc(128);
    if (!buf) return;
    memcpy(buf, "UAF_TEST", 8);
    blk_uaf_global = buf;  // 存入全局
    free(buf);              // 释放 (但全局未置NULL)
    if (blk_uaf_global) {
        // USE-AFTER-FREE: 解引用已释放指针
        printf("blk_uaf: freed[0]=%c\n", blk_uaf_global[0]);
    }
    blk_uaf_global = NULL;
}

void blk_uaf_safe() {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    memcpy(buf, "SAFE", 4);
    printf("blk_uaf_safe: %s\n", buf);
    free(buf);
    buf = NULL;
}

int main() {
    printf("cve_2021_32399 UAF test\n");
    blk_uaf_vuln();
    blk_uaf_safe();
    return 0;
}
