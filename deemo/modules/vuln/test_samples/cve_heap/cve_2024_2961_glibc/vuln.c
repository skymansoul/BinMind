/* CVE-2024-2961 — glibc iconv 堆溢出。
 * malloc(128) + memcpy(160)。
 * Expected: TP */
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *buf = (char *)malloc(128);
    if (!buf) return 1;
    char src[192];
    memset(src, 'E', sizeof(src));
    memcpy(buf, src, 160);                /* 越界 32B */
    free(buf);
    return 0;
}
