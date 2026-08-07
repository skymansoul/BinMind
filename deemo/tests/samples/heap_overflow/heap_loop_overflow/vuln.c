/**
 * heap_loop_overflow - Off-by-one in a for-loop writing to heap buffer
 *
 * This test case evaluates a static analysis tool's ability to infer
 * loop bounds. The loop condition uses 'i <= N' instead of 'i < N',
 * causing one extra byte to be written past the allocated buffer.
 *
 * Compile: gcc -g -O0 -o vuln vuln.c
 * Usage: ./vuln <value> <count>
 */

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    int N;
    char *buf;
    int i;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <count>\n", argv[0]);
        return 1;
    }

    N = atoi(argv[1]);
    if (N <= 0 || N > 4096) {
        fprintf(stderr, "Count must be between 1 and 4096\n");
        return 1;
    }

    /* Allocate N bytes on the heap */
    buf = (char *)malloc(N);  // VULN-GUARD: allocates N bytes
    if (!buf) {
        perror("malloc");
        return 1;
    }

    /* VULNERABLE: loop condition i <= N writes one byte past the buffer
     * When i == N, buf[N] is out-of-bounds (off-by-one write).
     * A tool must infer that the loop bound is one too many.
     */
    for (i = 0; i <= N; i++) {  // VULN: off-by-one in loop condition
        buf[i] = (char)(i & 0xFF);  // VULN: out-of-bounds write when i == N
    }

    printf("Wrote %d bytes to a buffer of size %d\n", N + 1, N);
    printf("Last byte written at offset %d (should be %d, one past the end)\n", N, N - 1);

    free(buf);
    return 0;
}
