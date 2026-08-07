/*
 * FP_no_guard_memcpy: UNGUARDED memcpy into heap buffer — TRUE POSITIVE.
 *
 * malloc(64) followed by memcpy with size that CAN exceed 64 if attacker
 * controls n. No guard protects the write.
 *
 * This should be DETECTED by both naive detector and GAPSBV.
 * GAPSBV should fail all three stages and correctly flag as KEEP.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void unguarded_copy(const char *src, size_t n) {
    char *buf = (char *)malloc(64);
    if (!buf) return;

    /* No guard on n — if n > 64, overflow.
     * GAPSBV analysis:
     *   Stage A: no cmp+jcc guard found → PASSES through
     *   Stage B: no path condition → PASSES through
     *   Stage C: no index var to track → PASSES through
     *   Result: KEEP (correct) */
    memcpy(buf, src, n);

    printf("buf[0] = %c\n", buf[0]);
    free(buf);
}

int main(int argc, char **argv) {
    char data[256];
    memset(data, 'B', sizeof(data));
    size_t n = (argc > 1) ? (size_t)atoi(argv[1]) : 128;
    unguarded_copy(data, n);
    return 0;
}
