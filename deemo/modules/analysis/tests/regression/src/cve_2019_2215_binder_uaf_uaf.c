#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// cve_2019_2215 UAF: ephemeral ptr: malloc in helper, free in caller, use later
char *binder_uaf_global = NULL;

void binder_uaf_vuln() {
    char *buf = (char *)malloc(128);
    if (!buf) return;
    memcpy(buf, "UAF_TEST", 8);
    binder_uaf_global = buf;  // 存入全局
    free(buf);              // 释放 (但全局未置NULL)
    if (binder_uaf_global) {
        // USE-AFTER-FREE: 解引用已释放指针
        printf("binder_uaf: freed[0]=%c\n", binder_uaf_global[0]);
    }
    binder_uaf_global = NULL;
}

void binder_uaf_safe() {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    memcpy(buf, "SAFE", 4);
    printf("binder_uaf_safe: %s\n", buf);
    free(buf);
    buf = NULL;
}

int main() {
    printf("cve_2019_2215 UAF test\n");
    binder_uaf_vuln();
    binder_uaf_safe();
    return 0;
}
