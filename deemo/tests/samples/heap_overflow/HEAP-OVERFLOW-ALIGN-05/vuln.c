/*
 * HEAP-OVERFLOW-ALIGN-05: Allocator alignment awareness
 *
 * Tests whether the detector understands allocator behavior:
 *
 * In glibc ptmalloc2, malloc() rounds up to the minimum chunk size
 * (typically 32 bytes on 64-bit, including metadata). So malloc(20)
 * actually yields an effective usable size of 32 - overhead.
 *
 *   write_safe():  malloc(20) + write 24 bytes.
 *      24 < 32 (effective chunk size), so this is SAFE.
 *      A detector WITHOUT an allocator model would FP on 24 > 20.
 *
 *   write_overflow(): malloc(20) + write 40 bytes.
 *      40 > 32 (effective chunk size), so this IS a heap overflow.
 *
 * Purpose: distinguish detectors with allocator modeling from naive
 * detectors that compare write size against the requested malloc size.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/*
 * SAFE with allocator awareness: malloc(20) yields ~24 usable bytes
 * (or 32B total chunk). Writing 24 bytes fits within the actual
 * allocation — no overflow at runtime. A naive detector comparing
 * 24 > 20 would incorrectly flag this.
 */
void write_safe(void) {
    char *buf = (char *)malloc(20);
    if (buf == NULL) {
        fprintf(stderr, "write_safe: malloc failed\n");
        return;
    }
    memset(buf, 'B', 24);  /* 24 <= effective size, safe at runtime */
    printf("write_safe: wrote 24 bytes to malloc(20) buffer (SAFE with alignment)\n");
    free(buf);
}

/*
 * REAL OVERFLOW: malloc(20) effective size is ~24-32 bytes.
 * Writing 40 bytes exceeds even the rounded-up chunk size.
 * This IS a heap overflow regardless of allocator model.
 */
void write_overflow(void) {
    char *buf = (char *)malloc(20);
    if (buf == NULL) {
        fprintf(stderr, "write_overflow: malloc failed\n");
        return;
    }
    memset(buf, 'C', 40);  /* 40 > 32 (effective size), REAL OVERFLOW */
    printf("write_overflow: wrote 40 bytes to malloc(20) buffer (OVERFLOW)\n");
    free(buf);
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "safe") == 0) {
        write_safe();
    } else if (argc > 1 && strcmp(argv[1], "overflow") == 0) {
        write_overflow();
    } else {
        printf("Usage: %s [safe|overflow]\n", argv[0]);
        printf("  safe     — malloc(20)+write(24): safe due to alignment\n");
        printf("  overflow — malloc(20)+write(40): real overflow\n");
    }

    return 0;
}
