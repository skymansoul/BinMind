/*
 * HEAP-OVERFLOW-REALLOC-07: realloc-based overflow
 *
 * Tests whether the detector tracks size changes through realloc().
 *
 * Flow:
 *   1. buf = malloc(32)     — initially 32 bytes
 *   2. buf = realloc(buf, 16) — shrunk to 16 bytes!
 *   3. memset(buf, 'F', 32) — OVERFLOW: 32 > 16 (new size)
 *
 * This IS a real heap overflow. The code continues to use the original
 * size (32) after realloc() has shrunk the buffer to 16 bytes.
 *
 * A detector that only tracks the initial malloc size and ignores
 * realloc() size changes will miss this bug entirely.
 *
 * Also includes a safe_realloc_resize() function for comparison:
 *   malloc(64) -> realloc(buf, 128) -> memset(buf, 100)
 *   This is safe after realloc GROWS the buffer.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/*
 * OVERFLOW: malloc(32), realloc shrinks to 16, then write 32 bytes.
 *
 * The developer forgot to update the memset size after shrinking the
 * buffer. This is a classic realloc-related bug: the pointer may remain
 * valid (realloc can return the same address on shrink), but the usable
 * size has changed.
 */
void realloc_shrink_overflow(void) {
    char *buf = (char *)malloc(32);
    if (buf == NULL) {
        fprintf(stderr, "realloc_shrink_overflow: malloc failed\n");
        return;
    }
    printf("After malloc:  buf = %p, size = 32\n", (void *)buf);

    /* Shrink the buffer to 16 bytes */
    buf = (char *)realloc(buf, 16);
    if (buf == NULL) {
        fprintf(stderr, "realloc_shrink_overflow: realloc failed\n");
        return;
    }
    printf("After realloc: buf = %p, size = 16 (SHRUNK)\n", (void *)buf);

    /*
     * HEAP OVERFLOW: writing 32 bytes to a 16-byte buffer.
     * The code still assumes the original 32-byte size.
     */
    memset(buf, 'F', 32);
    printf("Wrote 32 bytes to 16-byte buffer (OVERFLOW)\n");

    free(buf);
}

/*
 * SAFE: malloc(64), realloc GROWS to 128, then write 100 bytes.
 * This is fine because realloc increased the size.
 */
void realloc_grow_safe(void) {
    char *buf = (char *)malloc(64);
    if (buf == NULL) {
        fprintf(stderr, "realloc_grow_safe: malloc failed\n");
        return;
    }
    printf("After malloc:  buf = %p, size = 64\n", (void *)buf);

    buf = (char *)realloc(buf, 128);
    if (buf == NULL) {
        fprintf(stderr, "realloc_grow_safe: realloc failed\n");
        return;
    }
    printf("After realloc: buf = %p, size = 128 (GROWN)\n", (void *)buf);

    memset(buf, 'G', 100);  /* SAFE: 100 < 128 */
    printf("Wrote 100 bytes to 128-byte buffer (OK)\n");

    free(buf);
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "grow") == 0) {
        realloc_grow_safe();
    } else if (argc > 1 && strcmp(argv[1], "shrink") == 0) {
        realloc_shrink_overflow();
    } else {
        printf("Usage: %s [grow|shrink]\n", argv[0]);
        printf("  grow   — realloc GROWS buffer, write is safe\n");
        printf("  shrink — realloc SHRINKS buffer, write overflows\n");
    }

    return 0;
}
