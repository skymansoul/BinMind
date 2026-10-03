/* CVE-2021-34866 eBPF 验证器: 释放 map 后 strlen 访问. */
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
