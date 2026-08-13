#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// cve_2018_7566 UAF: double-free: malloc→free→free again
char *alsa_uaf_global = NULL;

void alsa_uaf_vuln() {
    char *buf = (char *)malloc(128);
    if (!buf) return;
    memcpy(buf, "UAF_TEST", 8);
    alsa_uaf_global = buf;  // 存入全局
    free(buf);              // 释放 (但全局未置NULL)
    if (alsa_uaf_global) {
        // USE-AFTER-FREE: 解引用已释放指针
        printf("alsa_uaf: freed[0]=%c\n", alsa_uaf_global[0]);
    }
    alsa_uaf_global = NULL;
}

void alsa_uaf_safe() {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    memcpy(buf, "SAFE", 4);
    printf("alsa_uaf_safe: %s\n", buf);
    free(buf);
    buf = NULL;
}

int main() {
    printf("cve_2018_7566 UAF test\n");
    alsa_uaf_vuln();
    alsa_uaf_safe();
    return 0;
}
