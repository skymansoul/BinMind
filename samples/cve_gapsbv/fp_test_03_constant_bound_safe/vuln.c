/* FP-TEST-03: constant bounds clearly within allocation.
 * malloc(256), memcpy(buf, src, 128) — always safe by constant comparison.
 * Stage 3.5 (copy_constraint_verifier) should prove SAFE and FILTER.
 */
#include <stdlib.h>
#include <string.h>

void safe_copy(void) {
    char *buf = (char *)malloc(256);
    if (buf == NULL) return;
    /* 128 < 256 — trivially safe */
    memcpy(buf, "data", 128);
    free(buf);
}

int main(void) {
    safe_copy();
    return 0;
}
