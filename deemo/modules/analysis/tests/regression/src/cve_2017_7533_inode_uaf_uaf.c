#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// cve_2017_7533 UAF: struct field: malloc→free→pass freed ptr to func
char *inode_uaf_global = NULL;

void inode_uaf_vuln() {
    char *buf = (char *)malloc(128);
    if (!buf) return;
    memcpy(buf, "UAF_TEST", 8);
    inode_uaf_global = buf;  // 存入全局
    free(buf);              // 释放 (但全局未置NULL)
    if (inode_uaf_global) {
        // USE-AFTER-FREE: 解引用已释放指针
        printf("inode_uaf: freed[0]=%c\n", inode_uaf_global[0]);
    }
    inode_uaf_global = NULL;
}

void inode_uaf_safe() {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    memcpy(buf, "SAFE", 4);
    printf("inode_uaf_safe: %s\n", buf);
    free(buf);
    buf = NULL;
}

int main() {
    printf("cve_2017_7533 UAF test\n");
    inode_uaf_vuln();
    inode_uaf_safe();
    return 0;
}
