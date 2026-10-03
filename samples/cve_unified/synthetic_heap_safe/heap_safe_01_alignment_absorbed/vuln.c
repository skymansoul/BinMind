/* heap_safe_01: malloc small, write slightly larger — allocator absorbs
 * SAFE: malloc(13) → actual chunk size 32B (glibc x86_64 min chunk)
 *       memcpy(..., 20) → 20 <= 32 effective → safe
 * Naive comparison: 20 > 13 → FALSE POSITIVE
 * With allocator model: effective(32) >= 20 → correctly filtered
 * Expected: FALSE POSITIVE for naive tools, CORRECTLY FILTERED by ours
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int safe_small_alloc(const char *input) {
    char *buf = (char *)malloc(13);   // actual chunk: 32B
    if (!buf) return -1;
    memcpy(buf, input, 20);           // 20 <= 32 effective → SAFE
    buf[19] = 0;
    printf("%s\n", buf);
    free(buf);
    return 0;
}

int main(void) {
    char dummy[32] = "test data 1234567";
    return safe_small_alloc(dummy);
}
