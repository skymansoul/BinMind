/*
 * TP_min_constrained: allocation size is min(user_input, MAX).
 *
 * Pattern: size = min(user_input, 256); buf = malloc(size);
 * A naive tool sees "size from user input" and panics.
 * GAPSBV should trace the min() constraint and see size ≤ 256.
 * If the write is ≤ 256 bytes, it's safe.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUF 256

static inline size_t safe_min(size_t a, size_t b) {
    return (a < b) ? a : b;
}

void process(size_t user_size, const char *data) {
    /* Constrained: allocation never exceeds MAX_BUF */
    size_t alloc_sz = safe_min(user_size, MAX_BUF);
    char *buf = (char *)malloc(alloc_sz);
    if (!buf) return;

    /* Write size = alloc_sz, which is ≤ MAX_BUF = 256 */
    memcpy(buf, data, alloc_sz);  /* SAFE: both are min(user_size, 256) */

    printf("buf[0] = %c\n", buf[0]);
    free(buf);
}

int main(int argc, char **argv) {
    size_t sz = (argc > 1) ? (size_t)atoi(argv[1]) : 100;
    char data[512];
    memset(data, 'A', sizeof(data));
    process(sz, data);
    return 0;
}
