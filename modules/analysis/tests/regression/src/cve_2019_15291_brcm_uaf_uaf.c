#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// cve_2019_15291 UAF: NULL bypass: free→skip null→reuse via global
char *brcm_uaf_global = NULL;

void brcm_uaf_vuln() {
    char *buf = (char *)malloc(128);
    if (!buf) return;
    memcpy(buf, "UAF_TEST", 8);
    brcm_uaf_global = buf;  // 存入全局
    free(buf);              // 释放 (但全局未置NULL)
    if (brcm_uaf_global) {
        // USE-AFTER-FREE: 解引用已释放指针
        printf("brcm_uaf: freed[0]=%c\n", brcm_uaf_global[0]);
    }
    brcm_uaf_global = NULL;
}

void brcm_uaf_safe() {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    memcpy(buf, "SAFE", 4);
    printf("brcm_uaf_safe: %s\n", buf);
    free(buf);
    buf = NULL;
}

int main() {
    printf("cve_2019_15291 UAF test\n");
    brcm_uaf_vuln();
    brcm_uaf_safe();
    return 0;
}
