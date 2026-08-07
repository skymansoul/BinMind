/**
 * heap_realloc_misuse - Use-after-realloc size confusion
 *
 * A buffer is allocated with malloc(64), then shrunk via realloc to 32 bytes.
 * The code then uses the original size (64) for memset, writing past the
 * end of the now-smaller realloc'd buffer. This tests whether a static
 * analyzer tracks buffer sizes across realloc calls.
 *
 * Compile: gcc -g -O0 -o vuln vuln.c
 * Usage: ./vuln
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *p;
    const size_t orig_size = 64;
    const size_t new_size = 32;

    /* Allocate 64 bytes */
    p = (char *)malloc(orig_size);
    if (!p) {
        perror("malloc");
        return 1;
    }

    printf("Allocated %zu bytes at %p\n", orig_size, (void *)p);

    /* Shrink the buffer to 32 bytes. The old pointer may be invalidated;
     * realloc can return a completely new allocation. */
    p = (char *)realloc(p, new_size);  // VULN-GUARD: buffer shrunk to 32 bytes
    if (!p) {
        perror("realloc");
        return 1;
    }

    printf("Reallocated to %zu bytes at %p\n", new_size, (void *)p);

    /* VULNERABLE: memset uses the ORIGINAL size (64) after realloc
     * has shrunk the buffer to 32 bytes. This writes 32 extra bytes
     * past the end of the allocation.
     * A tool must track that the buffer size changed from 64 to 32. */
    memset(p, 0, orig_size);  // VULN: using orig_size (64) instead of new_size (32)

    printf("Zeroed %zu bytes of a %zu-byte buffer -- overflow!\n", orig_size, new_size);

    free(p);
    return 0;
}
