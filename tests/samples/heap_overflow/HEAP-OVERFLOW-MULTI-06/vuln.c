/*
 * HEAP-OVERFLOW-MULTI-06: Multiple malloc+write pairs
 *
 * Tests that a detector correctly associates each heap write with the
 * right allocation when multiple malloc/memset pairs exist in one function.
 *
 *   safe_write():  buf1 = malloc(32), memset(buf1, 32, 'D')
 *                  This is safe: 32 bytes into 32-byte buffer.
 *
 *   overflow_write(): buf2 = malloc(16), memset(buf2, 64, 'E')
 *                  This IS an overflow: 64 bytes into 16-byte buffer.
 *
 * A detector that fails to properly track pointer-to-allocation mapping
 * might associate the 64-byte write with buf1 (32 bytes) instead of buf2
 * (16 bytes), or might conflate the two buffers entirely.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

void multi_buffers(void) {
    /*
     * Buffer 1: 32-byte allocation, 32-byte write. SAFE.
     * A detector must associate this memset with this malloc.
     */
    char *buf1 = (char *)malloc(32);
    if (buf1 == NULL) {
        fprintf(stderr, "multi_buffers: malloc(buf1) failed\n");
        return;
    }
    memset(buf1, 'D', 32);  /* SAFE: exactly fills the buffer */
    printf("buf1: wrote 32 bytes to malloc(32) (OK)\n");

    /*
     * Buffer 2: 16-byte allocation, 64-byte write. OVERFLOW.
     * A detector must correctly track that buf2 points to a 16-byte
     * allocation and NOT conflate it with buf1's 32-byte allocation.
     */
    char *buf2 = (char *)malloc(16);
    if (buf2 == NULL) {
        fprintf(stderr, "multi_buffers: malloc(buf2) failed\n");
        free(buf1);
        return;
    }
    memset(buf2, 'E', 64);  /* HEAP OVERFLOW: 64 > 16 */
    printf("buf2: wrote 64 bytes to malloc(16) (OVERFLOW)\n");

    /* Print first few bytes of each to prevent optimization */
    printf("buf1[0]=%c buf2[0]=%c\n", buf1[0], buf2[0]);

    free(buf1);
    free(buf2);
}

int main(void) {
    printf("=== HEAP-OVERFLOW-MULTI-06: Multiple allocation/write pairs ===\n");
    multi_buffers();
    return 0;
}
