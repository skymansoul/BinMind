/*
 * CVE-2023-23001-style — Multi-Buffer Off-by-One Heap Overflow
 *
 * This sample models a custom heap overflow pattern where multiple buffers
 * are allocated in a loop, but an off-by-one error in the buffer index
 * causes a write to the wrong (adjacent or out-of-bounds) buffer.
 *
 * The pattern:
 *   - Allocate an array of N heap buffers in a loop.
 *   - Iterate over the buffers to write data.
 *   - An off-by-one error in the loop bound writes past the last buffer
 *     or writes into an adjacent heap chunk.
 *
 * In this reproduction:
 *   - NUM_BUFS buffers are allocated, each of BUF_SIZE bytes.
 *   - A write loop with an off-by-one condition writes to NUM_BUFS
 *     entries instead of NUM_BUFS-1 (the last valid index).
 *   - The overflow corrupts heap metadata or data past the last buffer.
 *
 * Usage: ./vuln (no arguments needed — compile-time constants)
 *
 * VULNERABLE LINE: memset(bufs[i], 'X', BUF_SIZE);  // when i == NUM_BUFS
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NUM_BUFS  4
#define BUF_SIZE  32

int main(void) {
    char *bufs[NUM_BUFS];
    int i;

    printf("=== Allocating %d buffers of %d bytes each ===\n", NUM_BUFS, BUF_SIZE);

    /* Allocate NUM_BUFS heap buffers in a loop.                               */
    for (i = 0; i < NUM_BUFS; i++) {
        bufs[i] = (char *)malloc(BUF_SIZE);
        if (!bufs[i]) {
            fprintf(stderr, "malloc failed at index %d\n", i);
            /* Clean up previously allocated buffers.                          */
            for (int j = 0; j < i; j++) free(bufs[j]);
            return 1;
        }
        memset(bufs[i], 0x00, BUF_SIZE);
        printf("  bufs[%d] = %p\n", i, (void *)bufs[i]);
    }

    printf("\n=== Writing to buffers (off-by-one loop) ===\n");

    /*
     * [VULNERABLE] Off-by-one loop bound: i <= NUM_BUFS instead of i < NUM_BUFS.
     * The last iteration (i == NUM_BUFS) writes past the end of the bufs array,
     * treating whatever lies in memory at bufs[NUM_BUFS] as a valid pointer.
     * This is a heap buffer overflow via wrong buffer index.
     *
     * Correct bound should be:  for (i = 0; i < NUM_BUFS; i++)
     */
    for (i = 0; i <= NUM_BUFS; i++) {   /* OFF-BY-ONE: i <= NUM_BUFS          */
        printf("  writing to bufs[%d]\n", i);
        /*
         * When i == NUM_BUFS, bufs[NUM_BUFS] reads past the array and
         * dereferences whatever lives on the stack/heap at that offset.
         * This write corrupts memory at an arbitrary location.
         */
        memset(bufs[i], 'X', BUF_SIZE);
    }

    printf("\n=== Buffer contents after overflow ===\n");
    for (i = 0; i < NUM_BUFS; i++) {
        printf("  bufs[%d] = \"%.32s\"\n", i, bufs[i]);
    }

    /*
     * The overflow at i == NUM_BUFS may have corrupted heap metadata.
     * On many systems this will cause free() to crash or corrupt memory.
     */
    printf("\n=== Cleaning up ===\n");
    for (i = 0; i < NUM_BUFS; i++) {
        free(bufs[i]);
    }

    printf("!! OFF-BY-ONE INDEX: loop wrote to %d buffers (indices 0..%d)\n",
           NUM_BUFS + 1, NUM_BUFS);
    printf("!! but only %d buffers were allocated (valid indices 0..%d) !!\n",
           NUM_BUFS, NUM_BUFS - 1);

    return 0;
}
