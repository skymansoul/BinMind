#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// cve_2021_34866 UAF: verifier bypass: alloc→free→use via alias pointer
char *ebpf_uaf_global = NULL;

void ebpf_uaf_vuln() {
    char *buf = (char *)malloc(128);
    if (!buf) return;
    memcpy(buf, "UAF_TEST", 8);
    ebpf_uaf_global = buf;  // 存入全局
    free(buf);              // 释放 (但全局未置NULL)
    if (ebpf_uaf_global) {
        // USE-AFTER-FREE: 解引用已释放指针
        printf("ebpf_uaf: freed[0]=%c\n", ebpf_uaf_global[0]);
    }
    ebpf_uaf_global = NULL;
}

void ebpf_uaf_safe() {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    memcpy(buf, "SAFE", 4);
    printf("ebpf_uaf_safe: %s\n", buf);
    free(buf);
    buf = NULL;
}

int main() {
    printf("cve_2021_34866 UAF test\n");
    ebpf_uaf_vuln();
    ebpf_uaf_safe();
    return 0;
}
