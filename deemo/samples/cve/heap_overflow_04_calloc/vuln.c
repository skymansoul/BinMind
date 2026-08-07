/* heap_overflow_04: calloc overflow
 * CWE-122: buf=calloc(1,32); memcpy(buf, src, 64) → overflow by 32
 * Pattern: calloc and malloc have same alignment semantics, but calloc initializes to zero
 * Expected: TRUE POSITIVE
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int trigger_calloc_overflow(const char *input) {
    char *buf = (char *)calloc(1, 32);
    if (!buf) return -1;
    memcpy(buf, input, 64);  // OVERFLOW: 64 > 32
    printf("%.32s\n", buf);
    free(buf);
    return 0;
}

int main(int argc, char **argv) {
    char dummy[128];
    memset(dummy, 'C', 128);
    return trigger_calloc_overflow(dummy);
}
