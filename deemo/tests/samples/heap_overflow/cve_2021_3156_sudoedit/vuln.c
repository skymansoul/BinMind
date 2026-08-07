/*
 * CVE-2021-3156 — Sudoedit Heap Overflow (Baron Samedit) Reproduction
 *
 * This sample models the root cause of CVE-2021-3156: a heap buffer
 * overflow caused by an incorrect size calculation. The original sudo
 * vulnerability involved unescaping backslashes in command-line arguments
 * where the malloc used (size-1) but the write used the full user-controlled
 * size, bypassing the trailing null and overflowing the heap.
 *
 * In this reproduction:
 *   - The user supplies a size via argv[1].
 *   - malloc allocates (size - 1) bytes — one too few due to an
 *     off-by-one error in the allocation logic.
 *   - The write loop copies `size` bytes into that buffer, writing
 *     one byte past the end. For large sizes this corrupts heap metadata
 *     and adjacent chunks.
 *
 * Pattern:
 *   buf = malloc((size_t)(user_size - 1));   // off-by-one under-allocation
 *   memcpy(buf, src, (size_t)user_size);     // writes full user_size bytes
 *
 * A static analyser should detect the mismatch between the allocation
 * expression (user_size - 1) and the copy length (user_size).
 *
 * Usage: ./vuln <size>
 *   size — integer, must be >= 2. The program allocates (size-1) and
 *          writes `size` bytes, overflowing by 1 byte (minimum) or more.
 *
 * VULNERABLE LINE: memcpy(buf, payload, (size_t)user_size);
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <size>\n", argv[0]);
        fprintf(stderr, "  Allocates (size-1) bytes, writes `size` bytes -> overflow.\n");
        return 1;
    }

    int user_size = atoi(argv[1]);
    if (user_size < 2) {
        fprintf(stderr, "size must be >= 2 (need room for at least 1 byte overflow)\n");
        return 1;
    }

    printf("user_size   = %d\n", user_size);
    printf("alloc size  = %d (user_size - 1)\n", user_size - 1);
    printf("write size  = %d (full user_size)\n", user_size);

    /*
     * [VULNERABLE] Off-by-one under-allocation.
     * The programmer intended to account for a null terminator by subtracting
     * 1, but the write loop uses the full `user_size` — so 1 extra byte
     * (and potentially many more) overflows past the chunk boundary.
     */
    char *buf = (char *)malloc((size_t)(user_size - 1));
    if (!buf) { perror("malloc"); return 1; }
    memset(buf, 0x00, (size_t)(user_size - 1));

    /* Prepare payload — filled with 'X' (0x58) for visual identification.     */
    char *payload = (char *)malloc((size_t)user_size);
    if (!payload) { free(buf); perror("malloc payload"); return 1; }
    memset(payload, 'X', (size_t)user_size);

    /*
     * [VULNERABLE] memcpy writes `user_size` bytes, but the buffer only has
     * (user_size - 1) bytes. The last byte overflows past the heap chunk.
     * For large user_size values, many bytes overflow and corrupt adjacent
     * heap metadata.
     */
    memcpy(buf, payload, (size_t)user_size);

    printf("buf[0..%d]  = \"%s\"\n", user_size - 1, buf);
    printf("buf[%d]      = 0x%02x  <-- overflow byte (past allocation)\n",
           user_size - 1, (unsigned char)buf[user_size - 1]);
    printf("!! OFF-BY-ONE HEAP OVERFLOW: wrote %d bytes into %d-byte buffer !!\n",
           user_size, user_size - 1);

    free(payload);
    free(buf);
    return 0;
}
