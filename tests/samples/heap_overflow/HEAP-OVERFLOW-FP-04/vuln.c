/*
 * HEAP-OVERFLOW-FP-04: FALSE POSITIVE test
 *
 * This test contains TWO functions:
 *   1. safe_copy()  — malloc(64), memcpy length=48.  This is SAFE (48 < 64).
 *                     A good detector should NOT flag it.
 *   2. overflow_copy() — malloc(32), memcpy length=48. This IS an overflow.
 *                     A good detector SHOULD flag this one.
 *
 * Purpose: verify that the detector does not produce false positives for
 * legitimate operations where the copy size is clearly within bounds,
 * while still catching true overflows.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* SAFE: 48 bytes copied into a 64-byte buffer — no overflow */
void safe_copy(const char *input) {
    char *buf = (char *)malloc(64);
    if (buf == NULL) {
        fprintf(stderr, "safe_copy: malloc failed\n");
        return;
    }
    memcpy(buf, input, 48);
    printf("safe_copy: copied 48 bytes into 64-byte buffer (OK)\n");
    free(buf);
}

/* OVERFLOW: 48 bytes copied into a 32-byte buffer — heap overflow */
void overflow_copy(const char *input) {
    char *buf = (char *)malloc(32);
    if (buf == NULL) {
        fprintf(stderr, "overflow_copy: malloc failed\n");
        return;
    }
    memcpy(buf, input, 48);  /* HEAP OVERFLOW: 48 > 32 */
    printf("overflow_copy: copied 48 bytes into 32-byte buffer (OVERFLOW)\n");
    free(buf);
}

int main(int argc, char **argv) {
    /* Build a 100-byte input pattern so both functions have data to copy */
    char input[100];
    memset(input, 'A', sizeof(input));
    input[sizeof(input) - 1] = '\0';

    if (argc > 1 && strcmp(argv[1], "safe") == 0) {
        safe_copy(input);
    } else if (argc > 1 && strcmp(argv[1], "overflow") == 0) {
        overflow_copy(input);
    } else {
        printf("Usage: %s [safe|overflow]\n", argv[0]);
        printf("  safe     — demo safe_copy  (should NOT be flagged)\n");
        printf("  overflow — demo overflow_copy (SHOULD be flagged)\n");
    }

    return 0;
}
