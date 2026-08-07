/*
 * HEAP-OVERFLOW-BASIC-01 — Safe vs. Unsafe memcpy on the Same Heap Buffer
 *
 * This sample tests whether a detector can **distinguish** a safe memcpy
 * from an overflowing one when both operate on the SAME allocation.
 *
 * It allocates ONE buffer of 32 bytes, then performs TWO memcpy operations:
 *
 *   memcpy #1: size=20 (SAFE, 20 <= 32 — must NOT trigger a false positive)
 *   memcpy #2: size=48 (REAL OVERFLOW, 48 > 32 — must trigger a warning)
 *
 * A naive detector that flags "any memcpy with len > threshold" without
 * comparing to the actual buffer size would flag the first memcpy (FP).
 * A sound detector must compare the memcpy length against the buffer's
 * actual usable size and conclude:
 *   - 20 <= 32: safe, suppress warning.
 *   - 48 >  32: overflow, emit warning.
 *
 * Usage: ./vuln (no arguments needed — uses compile-time constants)
 *
 * SAFE LINES:       memcpy(buf, data_20, 20);   // 20 <= 32, safe
 * VULNERABLE LINE:  memcpy(buf, data_48, 48);   // 48 >  32, overflow!
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_SIZE   32
#define SAFE_LEN   20    /* 20 <= 32 -> always safe, must NOT trigger FP */
#define UNSAFE_LEN 48    /* 48 >  32 -> real heap overflow               */

int main(void) {
    setbuf(stdout, NULL);   /* unbuffered — ensure output before crash       */

    /*
     * Allocate a single 32-byte heap buffer.
     * Both memcpy calls write to this same buffer.
     */
    char *buf = (char *)malloc(BUF_SIZE);
    if (!buf) { perror("malloc"); return 1; }

    /* ==================================================================
     * memcpy #1: SAFE — copy 20 bytes into a 32-byte buffer.
     * A correct detector MUST NOT flag this as an overflow.
     * ================================================================*/
    memset(buf, 0x00, BUF_SIZE);

    char data_safe[SAFE_LEN];
    memset(data_safe, 'S', SAFE_LEN);

    memcpy(buf, data_safe, SAFE_LEN);   /* 20 <= 32 — SAFE, no overflow */

    printf("=== memcpy #1 (SAFE) ===\n");
    printf("buf        = \"%.20s\"\n", buf);
    printf("copy size  = %d, buffer size = %d -> %s\n", SAFE_LEN, BUF_SIZE,
           (SAFE_LEN <= BUF_SIZE) ? "OK" : "OVERFLOW");

    /* ==================================================================
     * memcpy #2: UNSAFE — copy 48 bytes into a 32-byte buffer.
     * This IS a genuine heap overflow: writes 16 bytes past the chunk.
     * A correct detector MUST flag this.
     * ================================================================*/
    memset(buf, 0x00, BUF_SIZE);         /* reset buffer state            */

    char data_unsafe[UNSAFE_LEN];
    memset(data_unsafe, 'U', UNSAFE_LEN);

    memcpy(buf, data_unsafe, UNSAFE_LEN);   /* 48 > 32 — OVERFLOW!       */

    printf("\n=== memcpy #2 (UNSAFE) ===\n");
    printf("buf        = \"%.48s\"  <-- truncated display\n", buf);
    printf("copy size  = %d, buffer size = %d -> %s\n", UNSAFE_LEN, BUF_SIZE,
           (UNSAFE_LEN <= BUF_SIZE) ? "OK" : "OVERFLOW");
    printf("!! HEAP OVERFLOW: wrote %d bytes into a %d-byte buffer !!\n",
           UNSAFE_LEN, BUF_SIZE);
    printf("!! Bytes %d..%d overflow past the chunk boundary.\n",
           BUF_SIZE, UNSAFE_LEN - 1);

    free(buf);

    /*
     * Summary for detector evaluation:
     *   - memcpy #1 (size=20): should produce ZERO warnings (no FP).
     *   - memcpy #2 (size=48): should produce ONE warning (TP).
     *   - A detector that flags both is producing a false positive on #1.
     */
    printf("\n=== DETECTOR EVALUATION ===\n");
    printf("memcpy #1 (len=%d, buf=%d): should be CLEAN (no warning)\n",
           SAFE_LEN, BUF_SIZE);
    printf("memcpy #2 (len=%d, buf=%d): should be FLAGGED (heap overflow)\n",
           UNSAFE_LEN, BUF_SIZE);

    return 0;
}
