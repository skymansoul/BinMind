/* CVE-2020-25211 netfilter nftables: 释放规则后打印. */
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    free(p);
    printf("%s\n", p);
    return 0;
}
