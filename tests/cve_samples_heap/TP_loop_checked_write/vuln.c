/*
 * TP_loop_checked_write: write inside a loop bounded by allocation size.
 *
 * Pattern: for(i=0; i<alloc_sz; i++) buf[i] = src[i];
 * The loop bound equals the allocation size, so no overflow occurs.
 * Naive detector: sees malloc(N) + N stores → flags overflow.
 * GAPSBV should: infer loop bound from cmp, recognize i∈[0,N) → FILTER.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void copy_loop(const char *src, size_t len) {
    char *buf = (char *)malloc(len);
    if (!buf) return;

    for (size_t i = 0; i < len; i++) {
        buf[i] = src[i];  /* SAFE: i < len == alloc_size */
    }

    printf("copied %zu bytes\n", len);
    free(buf);
}

int main(void) {
    copy_loop("hello world", 11);
    return 0;
}
