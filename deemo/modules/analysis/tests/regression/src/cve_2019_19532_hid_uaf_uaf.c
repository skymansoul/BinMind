#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// cve_2019_19532 UAF: out-of-order: two mallocs, free first, use second ptr
char *hid_uaf_global = NULL;

void hid_uaf_vuln() {
    char *buf = (char *)malloc(128);
    if (!buf) return;
    memcpy(buf, "UAF_TEST", 8);
    hid_uaf_global = buf;  // 存入全局
    free(buf);              // 释放 (但全局未置NULL)
    if (hid_uaf_global) {
        // USE-AFTER-FREE: 解引用已释放指针
        printf("hid_uaf: freed[0]=%c\n", hid_uaf_global[0]);
    }
    hid_uaf_global = NULL;
}

void hid_uaf_safe() {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    memcpy(buf, "SAFE", 4);
    printf("hid_uaf_safe: %s\n", buf);
    free(buf);
    buf = NULL;
}

int main() {
    printf("cve_2019_19532 UAF test\n");
    hid_uaf_vuln();
    hid_uaf_safe();
    return 0;
}
