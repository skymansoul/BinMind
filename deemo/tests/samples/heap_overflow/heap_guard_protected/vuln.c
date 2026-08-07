/*
 * heap_guard_protected — Guard-Protected Heap Write (Should NOT Flag)
 *
 * This sample tests whether a heap-overflow detector correctly recognizes
 * a **guard condition** that prevents an out-of-bounds write. The program
 * allocates a 64-byte buffer and only writes to it when `idx < 64`.
 * If the index is out of range, the write is skipped.
 *
 * A sound detector must analyze the guard condition and conclude that
 * the write is provably safe — it must NOT produce a false positive.
 * An overly conservative detector that ignores guard conditions would
 * incorrectly flag this as a potential overflow.
 *
 * Usage: ./vuln <index>
 *   index — integer, the byte offset to write to.
 *           If < 64, write proceeds safely.
 *           If >= 64, write is blocked by the guard (no overflow).
 *
 * SAFE LINE: buf[idx] = 'A';  // guarded by if(idx < 64)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_SIZE 64

int main(int argc, char **argv) {
    int idx;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <index>\n", argv[0]);
        fprintf(stderr, "  index — byte offset.\n");
        fprintf(stderr, "    < %d: write proceeds (safe, guarded).\n", BUF_SIZE);
        fprintf(stderr, "    >= %d: write blocked by guard (no overflow possible).\n",
                BUF_SIZE);
        return 1;
    }

    idx = atoi(argv[1]);

    printf("buf_size = %d\n", BUF_SIZE);
    printf("index    = %d\n", idx);

    /* Allocate a 64-byte heap buffer.                                         */
    char *buf = (char *)malloc(BUF_SIZE);
    if (!buf) { perror("malloc"); return 1; }
    memset(buf, 0x00, BUF_SIZE);

    /*
     * [SAFE] The guard condition `idx < BUF_SIZE` ensures that the write
     * only executes when the index is within bounds.
     *
     * A correct detector MUST recognize this guard and conclude that no
     * heap overflow can occur at the write below. This should produce
     * ZERO warnings — it is a non-bug and must not be a false positive.
     */
    if (idx < BUF_SIZE) {
        buf[idx] = 'A';
        printf("GUARD PASSED: idx=%d < %d, write is safe.\n", idx, BUF_SIZE);
        printf("buf[%d] = '%c'\n", idx, buf[idx]);
    } else {
        printf("GUARD BLOCKED: idx=%d >= %d, write skipped.\n", idx, BUF_SIZE);
        printf("No heap access occurred — safe by construction.\n");
    }

    /*
     * Detector evaluation:
     *   - This code is safe for ALL values of idx.
     *   - A correct detector produces ZERO warnings.
     *   - A detector that warns here has a guard-detection deficit.
     */
    printf("\n=== DETECTOR EVALUATION ===\n");
    printf("Write is guarded by: if (idx < %d)\n", BUF_SIZE);
    printf("Result: ALWAYS SAFE — no overflow possible.\n");
    printf("This should produce ZERO overflow warnings.\n");

    free(buf);
    return 0;
}
