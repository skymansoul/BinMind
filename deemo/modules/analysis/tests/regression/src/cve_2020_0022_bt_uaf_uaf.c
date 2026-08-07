#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// cve_2020_0022 UAF: callback UAF: malloc→free in cb→use in caller
char *bt_uaf_global = NULL;

void bt_uaf_vuln() {
    char *buf = (char *)malloc(128);
    if (!buf) return;
    memcpy(buf, "UAF_TEST", 8);
    bt_uaf_global = buf;  // 存入全局
    free(buf);              // 释放 (但全局未置NULL)
    if (bt_uaf_global) {
        // USE-AFTER-FREE: 解引用已释放指针
        printf("bt_uaf: freed[0]=%c\n", bt_uaf_global[0]);
    }
    bt_uaf_global = NULL;
}

void bt_uaf_safe() {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    memcpy(buf, "SAFE", 4);
    printf("bt_uaf_safe: %s\n", buf);
    free(buf);
    buf = NULL;
}

int main() {
    printf("cve_2020_0022 UAF test\n");
    bt_uaf_vuln();
    bt_uaf_safe();
    return 0;
}
