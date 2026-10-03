/* CVE-2023-2513 — Linux kernel ext4 buffer head use-after-free but with heap overflow pattern:
 * bitmap buffer allocation with off-by-one rounding → adjacent memory corruption */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    unsigned nr_blocks = 33;  // needs 5 bytes (ceil(33/8))
    unsigned alloc = (nr_blocks + 7) / 8;  // 5 bytes, but not aligned
    char *buf = (char *)malloc(alloc);
    if (buf) {
        memset(buf, 0xFF, alloc + 1);  // HEAP OVERFLOW: off-by-one
        printf("CVE-2023-2513: alloc=%u write=%u\n", alloc, alloc + 1);
        free(buf);
    }
    return 0;
}
