/* heap_safe_02: malloc(N) + memcpy(N) — exactly same size, safe
 * SAFE: malloc(64), memcpy(64 bytes) → safe
 * Expected: CORRECT SAFE (no detection should be raised)
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int safe_exact_size(const char *input) {
    size_t sz = 64;
    char *buf = (char *)malloc(sz);
    if (!buf) return -1;
    memcpy(buf, input, sz);   // exact same size → SAFE
    buf[sz - 1] = 0;
    printf("%s\n", buf);
    free(buf);
    return 0;
}

int main(void) {
    char dummy[64];
    memset(dummy, 'S', 64);
    dummy[63] = 0;
    return safe_exact_size(dummy);
}
