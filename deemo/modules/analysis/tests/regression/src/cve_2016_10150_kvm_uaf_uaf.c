#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// cve_2016_10150 UAF: global ptr: malloc→free→use via global variable
char *kvm_uaf_global = NULL;

void kvm_uaf_vuln() {
    char *buf = (char *)malloc(128);
    if (!buf) return;
    memcpy(buf, "UAF_TEST", 8);
    kvm_uaf_global = buf;  // 存入全局
    free(buf);              // 释放 (但全局未置NULL)
    if (kvm_uaf_global) {
        // USE-AFTER-FREE: 解引用已释放指针
        printf("kvm_uaf: freed[0]=%c\n", kvm_uaf_global[0]);
    }
    kvm_uaf_global = NULL;
}

void kvm_uaf_safe() {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    memcpy(buf, "SAFE", 4);
    printf("kvm_uaf_safe: %s\n", buf);
    free(buf);
    buf = NULL;
}

int main() {
    printf("cve_2016_10150 UAF test\n");
    kvm_uaf_vuln();
    kvm_uaf_safe();
    return 0;
}
