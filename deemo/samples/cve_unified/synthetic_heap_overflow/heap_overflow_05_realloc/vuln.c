/* heap_overflow_05: realloc shrink then overflow
 * CWE-122: buf=malloc(128); buf=realloc(buf,32); memcpy(buf, src, 64)
 * After realloc to 32, the old 128-byte memory may be freed.
 * Writing 64 bytes into the new 32-byte allocation overflows.
 * Expected: TRUE POSITIVE
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int trigger_realloc_overflow(const char *input) {
    char *buf = (char *)malloc(128);
    if (!buf) return -1;
    buf = (char *)realloc(buf, 32);  // shrink to 32
    if (!buf) return -1;
    memcpy(buf, input, 64);           // OVERFLOW: 64 > 32
    printf("%.32s\n", buf);
    free(buf);
    return 0;
}

int main(int argc, char **argv) {
    char dummy[128];
    memset(dummy, 'R', 128);
    return trigger_realloc_overflow(dummy);
}
