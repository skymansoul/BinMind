#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// cve_2022_0995 UAF: two-phase: alloc→free in cleanup→use via cached ref
char *watch_uaf_global = NULL;

void watch_uaf_vuln() {
    char *buf = (char *)malloc(128);
    if (!buf) return;
    memcpy(buf, "UAF_TEST", 8);
    watch_uaf_global = buf;  // 存入全局
    free(buf);              // 释放 (但全局未置NULL)
    if (watch_uaf_global) {
        // USE-AFTER-FREE: 解引用已释放指针
        printf("watch_uaf: freed[0]=%c\n", watch_uaf_global[0]);
    }
    watch_uaf_global = NULL;
}

void watch_uaf_safe() {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    memcpy(buf, "SAFE", 4);
    printf("watch_uaf_safe: %s\n", buf);
    free(buf);
    buf = NULL;
}

int main() {
    printf("cve_2022_0995 UAF test\n");
    watch_uaf_vuln();
    watch_uaf_safe();
    return 0;
}
