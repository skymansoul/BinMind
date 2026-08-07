#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int main(void) {
    uint32_t big = 0x10000;  /* 65536 */
    uint16_t small = (uint16_t)big;  /* truncation: 65536 → 0 */
    /* alloc(0) may succeed → use as if 65536 bytes available */
    char *buf = (char *)malloc(small ? small : 1);
    if (!buf) return 1;
    /* OVERFLOW intent: big=65536 but only 1 byte allocated */
    printf("16-bit truncated: %u → %u\n", big, small);
    free(buf);
    return 0;
}
