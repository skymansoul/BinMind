#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// cve_2018_17182 UAF: conditional: free on one path, use on another
char *vmac_uaf_global = NULL;

void vmac_uaf_vuln() {
    char *buf = (char *)malloc(128);
    if (!buf) return;
    memcpy(buf, "UAF_TEST", 8);
    vmac_uaf_global = buf;  // 存入全局
    free(buf);              // 释放 (但全局未置NULL)
    if (vmac_uaf_global) {
        // USE-AFTER-FREE: 解引用已释放指针
        printf("vmac_uaf: freed[0]=%c\n", vmac_uaf_global[0]);
    }
    vmac_uaf_global = NULL;
}

void vmac_uaf_safe() {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    memcpy(buf, "SAFE", 4);
    printf("vmac_uaf_safe: %s\n", buf);
    free(buf);
    buf = NULL;
}

int main() {
    printf("cve_2018_17182 UAF test\n");
    vmac_uaf_vuln();
    vmac_uaf_safe();
    return 0;
}
