#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// cve_2023_0461 UAF: chained: alloc→free→use in completion handler
char *io_uring_uaf_global = NULL;

void io_uring_uaf_vuln() {
    char *buf = (char *)malloc(128);
    if (!buf) return;
    memcpy(buf, "UAF_TEST", 8);
    io_uring_uaf_global = buf;  // 存入全局
    free(buf);              // 释放 (但全局未置NULL)
    if (io_uring_uaf_global) {
        // USE-AFTER-FREE: 解引用已释放指针
        printf("io_uring_uaf: freed[0]=%c\n", io_uring_uaf_global[0]);
    }
    io_uring_uaf_global = NULL;
}

void io_uring_uaf_safe() {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    memcpy(buf, "SAFE", 4);
    printf("io_uring_uaf_safe: %s\n", buf);
    free(buf);
    buf = NULL;
}

int main() {
    printf("cve_2023_0461 UAF test\n");
    io_uring_uaf_vuln();
    io_uring_uaf_safe();
    return 0;
}
