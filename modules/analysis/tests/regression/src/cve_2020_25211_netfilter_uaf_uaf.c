#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// cve_2020_25211 UAF: pass-as-arg: malloc→free→pass freed to function
char *netfilter_uaf_global = NULL;

void netfilter_uaf_vuln() {
    char *buf = (char *)malloc(128);
    if (!buf) return;
    memcpy(buf, "UAF_TEST", 8);
    netfilter_uaf_global = buf;  // 存入全局
    free(buf);              // 释放 (但全局未置NULL)
    if (netfilter_uaf_global) {
        // USE-AFTER-FREE: 解引用已释放指针
        printf("netfilter_uaf: freed[0]=%c\n", netfilter_uaf_global[0]);
    }
    netfilter_uaf_global = NULL;
}

void netfilter_uaf_safe() {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    memcpy(buf, "SAFE", 4);
    printf("netfilter_uaf_safe: %s\n", buf);
    free(buf);
    buf = NULL;
}

int main() {
    printf("cve_2020_25211 UAF test\n");
    netfilter_uaf_vuln();
    netfilter_uaf_safe();
    return 0;
}
