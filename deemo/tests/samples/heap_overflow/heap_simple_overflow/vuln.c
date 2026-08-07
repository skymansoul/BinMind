/**
 * heap_simple_overflow - Simplest possible heap overflow (baseline test)
 *
 * malloc(32) followed by memcpy of 128 bytes. This is the most trivial
 * detectable heap overflow -- the allocation size and write size are both
 * compile-time constants, and the write size (128) vastly exceeds the
 * allocation size (32). Any static analysis tool with basic heap buffer
 * tracking should flag this.
 *
 * Compile: gcc -g -O0 -o vuln vuln.c
 * Usage: ./vuln
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALLOC_SIZE  32
#define WRITE_SIZE 128

int main(void) {
    char *buf;
    char src[WRITE_SIZE];
    int i;

    /* Prepare source data */
    for (i = 0; i < WRITE_SIZE; i++) {
        src[i] = (char)('A' + (i % 26));
    }

    /* Allocate only 32 bytes on the heap */
    buf = (char *)malloc(ALLOC_SIZE);  // VULN-GUARD: only 32 bytes allocated
    if (!buf) {
        perror("malloc");
        return 1;
    }

    /* VULNERABLE: memcpy writes 128 bytes into a 32-byte buffer.
     * This overflows by 96 bytes, corrupting heap metadata and
     * adjacent heap chunks. The sizes are compile-time constants
     * making this trivially detectable. */
    memcpy(buf, src, WRITE_SIZE);  // VULN: 128 > 32, trivial overflow

    printf("Wrote %d bytes into a %d-byte heap buffer\n", WRITE_SIZE, ALLOC_SIZE);

    free(buf);
    return 0;
}
