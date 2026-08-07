/* heap_overflow_02: Loop-based heap overflow (array write past bound)
 * CWE-122: for(i=0;i<128;i++) buf[i]=x where buf=malloc(64)
 * Pattern: loop write bound (128) > allocation size (64)
 * Expected: TRUE POSITIVE (requires loop bound inference)
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int trigger_loop_overflow(void) {
    size_t alloc_sz = 64;
    size_t loop_bound = 128;
    char *buf = (char *)malloc(alloc_sz);
    if (!buf) return -1;
    for (size_t i = 0; i < loop_bound; i++) {
        buf[i] = 'A';  // OVERFLOW when i >= 64
    }
    buf[loop_bound - 1] = 0;
    printf("%s\n", buf);
    free(buf);
    return 0;
}

int main(void) {
    return trigger_loop_overflow();
}
