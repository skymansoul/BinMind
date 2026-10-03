/* heap_overflow_03: Pointer alias overflow
 * CWE-122: buf=malloc(80); ptr=buf+60; memcpy(ptr, src, 40) → overflow by 20
 * Pattern: write through aliased pointer exceeds allocation
 * Expected: TRUE POSITIVE (requires alias/pointer analysis)
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int trigger_alias_overflow(const char *input) {
    char *buf = (char *)malloc(80);
    if (!buf) return -1;
    char *ptr = buf + 60;          // ptr points to buf[60]
    memcpy(ptr, input, 40);        // writes buf[60..100), but alloc is 80 → overflow by 20
    printf("%s\n", buf);
    free(buf);
    return 0;
}

int main(int argc, char **argv) {
    char dummy[128];
    memset(dummy, 'B', 128);
    dummy[127] = 0;
    return trigger_alias_overflow(dummy);
}
