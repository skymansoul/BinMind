/* CVE-2020-10713 — grub2 堆溢出 (固定大小写入越界)。
 * malloc(32) + memset(64)。
 * Expected: TP */
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *buf = (char *)malloc(32);
    if (!buf) return 1;
    memset(buf, 0x41, 64);                /* 越界 32B */
    free(buf);
    return 0;
}
