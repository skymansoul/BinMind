#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// cve_2020_14386 UAF: error path: malloc→free on error→use on retry
char *afpacket_uaf_global = NULL;

void afpacket_uaf_vuln() {
    char *buf = (char *)malloc(128);
    if (!buf) return;
    memcpy(buf, "UAF_TEST", 8);
    afpacket_uaf_global = buf;  // 存入全局
    free(buf);              // 释放 (但全局未置NULL)
    if (afpacket_uaf_global) {
        // USE-AFTER-FREE: 解引用已释放指针
        printf("afpacket_uaf: freed[0]=%c\n", afpacket_uaf_global[0]);
    }
    afpacket_uaf_global = NULL;
}

void afpacket_uaf_safe() {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    memcpy(buf, "SAFE", 4);
    printf("afpacket_uaf_safe: %s\n", buf);
    free(buf);
    buf = NULL;
}

int main() {
    printf("cve_2020_14386 UAF test\n");
    afpacket_uaf_vuln();
    afpacket_uaf_safe();
    return 0;
}
