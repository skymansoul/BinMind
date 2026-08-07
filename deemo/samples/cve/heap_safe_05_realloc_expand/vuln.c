/* heap_safe_05: realloc expand, then write within new size
 * SAFE: buf=malloc(32); buf=realloc(buf,128); memcpy(buf,src,64) → safe
 * Pattern: realloc expands allocation before write
 * Naive tools may track only the original malloc(32) → FALSE POSITIVE
 * Expected: CORRECT SAFE (realloc expanded to 128 before write)
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int safe_realloc_expand(const char *input) {
    char *buf = (char *)malloc(32);
    if (!buf) return -1;
    buf = (char *)realloc(buf, 128);  // expand to 128
    if (!buf) return -1;
    memcpy(buf, input, 64);            // 64 <= 128 → SAFE
    buf[63] = 0;
    printf("%s\n", buf);
    free(buf);
    return 0;
}

int main(void) {
    char dummy[64];
    memset(dummy, 'E', 64);
    dummy[63] = 0;
    return safe_realloc_expand(dummy);
}
