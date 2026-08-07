/* CVE-2023-2513 — kernel bpf 堆写越界。
 * malloc(48) + memset(96)。
 * Expected: TP */
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *buf = (char *)malloc(48);
    if (!buf) return 1;
    memset(buf, 0x42, 96);                /* 越界 48B */
    free(buf);
    return 0;
}
