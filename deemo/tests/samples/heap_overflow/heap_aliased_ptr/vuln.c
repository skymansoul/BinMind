/*
 * heap_aliased_ptr — Use-After-Free Leading to Heap Overflow Pattern
 *
 * This sample tests whether a detector can track pointer aliasing and
 * detect a use-after-free that leads to a heap overflow. Two pointers
 * (p and q) point to the same malloc'd buffer. After q is passed to free(),
 * writing through p constitutes a use-after-free that can overflow into
 * memory now owned by another allocation or by the allocator.
 *
 * The pattern:
 *   p = malloc(N);
 *   q = p;               // q aliases p
 *   free(q);             // memory returned to allocator
 *   memcpy(p, src, M);   // USE-AFTER-FREE + potential overflow (M > N)
 *
 * Even if M == N, this is still a use-after-free. But when M > N, it
 * becomes a use-after-free leading to a heap overflow — the freed chunk's
 * metadata or an adjacent reallocated chunk can be corrupted.
 *
 * Usage: ./vuln (no arguments needed — compile-time constants)
 *
 * ALIASING UAF LINE:   char *q = p;     // q is an alias of p
 * FREE LINE:           free(q);         // memory freed via alias
 * VULNERABLE LINE:     memcpy(p, data, OVERFLOW_SIZE);  // UAF + overflow
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_SIZE       64
#define OVERFLOW_SIZE  128    /* twice the allocation -> UAF heap overflow */

int main(void) {
    printf("=== Alias / Use-After-Free Heap Overflow Test ===\n");
    printf("buf_size      = %d\n", BUF_SIZE);
    printf("overflow_size = %d\n", OVERFLOW_SIZE);

    /* Allocate a 64-byte buffer. p owns the memory.                          */
    char *p = (char *)malloc(BUF_SIZE);
    if (!p) { perror("malloc"); return 1; }
    memset(p, 0xAA, BUF_SIZE);
    printf("p = %p (malloc'd %d bytes)\n", (void *)p, BUF_SIZE);

    /*
     * q is an alias of p — both point to the same heap chunk.
     * A flow-sensitive alias analysis must track that p and q
     * refer to the same allocation.
     */
    char *q = p;
    printf("q = %p (alias of p)\n", (void *)q);

    /*
     * Free the buffer through q. After this call, both p and q are
     * dangling pointers. The memory may be reused by subsequent
     * allocations or returned to the OS.
     */
    free(q);
    printf("free(q) called — both p and q are now dangling\n");

    /*
     * [VULNERABLE] Use-after-free: writing through p after the buffer
     * was freed via q. This is a USE-AFTER-FREE.
     *
     * Moreover, OVERFLOW_SIZE (128) > BUF_SIZE (64), so even if the
     * buffer were still valid, this would be a heap overflow.
     * Combined: UAF + heap overflow.
     */
    char data[OVERFLOW_SIZE];
    memset(data, 'Z', OVERFLOW_SIZE);

    printf("Writing %d bytes through dangling pointer p...\n", OVERFLOW_SIZE);
    memcpy(p, data, OVERFLOW_SIZE);

    printf("p[0..15]  = %.16s  <-- written via dangling pointer\n", p);
    printf("p[16..31] = %.16s  <-- UAF / overflow region\n", p + 16);
    printf("p[32..47] = %.16s  <-- UAF / overflow region\n", p + 32);
    printf("p[48..63] = %.16s  <-- UAF / overflow region\n", p + 48);
    printf("p[64..79] = %.16s  <-- beyond original allocation!\n", p + 64);
    printf("p[80..95] = %.16s  <-- deep overflow into heap!\n", p + 80);

    printf("\n!! USE-AFTER-FREE + HEAP OVERFLOW !!\n");
    printf("!! Buffer freed at %p, then written with %d bytes !!\n",
           (void *)p, OVERFLOW_SIZE);
    printf("!! Original allocation was only %d bytes.\n", BUF_SIZE);

    /* Do NOT free(p) again — already freed via q.                            */
    return 0;
}
