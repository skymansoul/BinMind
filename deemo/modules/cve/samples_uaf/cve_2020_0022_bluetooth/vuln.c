/* CVE-2020-0022 Bluetooth L2CAP: 释放 skb 后 strlen 计算长度. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    free(p);
    size_t n = strlen(p);
    printf("len=%zu\n", n);
    return 0;
}
