#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// cve_2017_2636 UAF: local ptr: malloc→free→deref in same function
char *kernel_uaf_global = NULL;

void kernel_uaf_vuln() {
    char *buf = (char *)malloc(128);
    if (!buf) return;
    memcpy(buf, "UAF_TEST", 8);
    kernel_uaf_global = buf;  // 存入全局
    free(buf);              // 释放 (但全局未置NULL)
    if (kernel_uaf_global) {
        // USE-AFTER-FREE: 解引用已释放指针
        printf("kernel_uaf: freed[0]=%c\n", kernel_uaf_global[0]);
    }
    kernel_uaf_global = NULL;
}

void kernel_uaf_safe() {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    memcpy(buf, "SAFE", 4);
    printf("kernel_uaf_safe: %s\n", buf);
    free(buf);
    buf = NULL;
}

int main() {
    printf("cve_2017_2636 UAF test\n");
    kernel_uaf_vuln();
    kernel_uaf_safe();
    return 0;
}
