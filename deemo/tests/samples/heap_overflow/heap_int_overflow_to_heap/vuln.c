/*
 * heap_int_overflow_to_heap — Integer Overflow Leading to Heap Overflow
 *
 * This sample tests whether a detector can chain an integer overflow
 * through to a heap buffer overflow. The program uses `malloc(count * size)`
 * where count and size are user-controlled. When their product overflows
 * a 32-bit integer (wrapping to a small value), a tiny buffer is allocated
 * but the subsequent write uses the full (large) product, overflowing the
 * undersized allocation.
 *
 * Pattern:
 *   uint32_t total = count * size;    // integer overflow: wraps to small
 *   buf = malloc(total);              // allocates much less than expected
 *   memcpy(buf, src, count * size);   // would need the full product -> OVERFLOW
 *
 * For example, with count=0x40000001 and size=4:
 *   - count * size = 0x100000004 -> wraps to 4 (32-bit overflow)
 *   - malloc(4) allocates 4 bytes
 *   - memcpy writes 0x100000004 bytes (intention) or the huge count*size
 *
 * Usage: ./vuln [count] [size]
 *   count — unsigned integer (default: 0x40000001, triggers overflow*4=4)
 *   size  — unsigned integer (default: 4)
 *
 * VULNERABLE LINE: buf = malloc((size_t)(count * size));  // product overflows
 * VULNERABLE LINE: memcpy(buf, payload, (size_t)(count * size)); // same overflow
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int main(int argc, char **argv) {
    /*
     * Default values that trigger integer overflow on 32-bit:
     *   0x40000001 * 4 = 0x1_00000004  -> wraps to 4 on uint32_t
     *   malloc(4) but the intended allocation was ~1GB.
     */
    uint32_t count = 0x40000001;
    uint32_t size  = 4;

    if (argc >= 2) {
        count = (uint32_t)strtoul(argv[1], NULL, 0);
    }
    if (argc >= 3) {
        size = (uint32_t)strtoul(argv[2], NULL, 0);
    }

    setbuf(stdout, NULL);   /* unbuffered — ensure output before crash          */

    /* Compute the product — this may overflow.                                */
    uint32_t total = count * size;
    uint64_t real_total = (uint64_t)count * (uint64_t)size;

    printf("count         = %u (0x%x)\n", count, count);
    printf("size          = %u (0x%x)\n", size, size);
    printf("count * size  = %u (0x%x)  <-- 32-bit product (MAY OVERFLOW)\n",
           total, total);
    printf("real product  = %llu (0x%llx)  <-- 64-bit (no overflow)\n",
           (unsigned long long)real_total, (unsigned long long)real_total);

    int overflowed = (real_total != (uint64_t)total);
    if (overflowed) {
        printf("!! INTEGER OVERFLOW DETECTED: 32-bit product wrapped !!\n");
        printf("   Expected ~%llu bytes, but only %u bytes will be allocated.\n",
               (unsigned long long)real_total, total);
    }

    /*
     * [VULNERABLE] malloc uses the overflowed 32-bit product.
     * When the product wraps to a small value, this allocates far less
     * memory than the subsequent write will use.
     */
    char *buf = (char *)malloc((size_t)total);
    if (!buf) { perror("malloc"); return 1; }

    printf("\nAllocated %u bytes at %p\n", total, (void *)buf);

    /*
     * [VULNERABLE] The write uses (count * size) — the same overflowed
     * value — but this can still be problematic if the code later uses
     * the intended (un-overflowed) size. For full detection, we model the
     * worst case: allocate with the overflowed size, but write with the
     * intended size (or a size derived from the full count and size).
     *
     * We demonstrate this by writing the smaller of (real_total) or a
     * large constant, simulating code that recalculates the allocation
     * need independently and writes more than allocated.
     */

    /* Prepare payload up to what the code "thinks" is the allocation size.    */
    size_t write_size;
    if (overflowed) {
        /* Simulate the bug: code uses the intended size for the write.         */
        write_size = (size_t)(real_total > 4096 ? 4096 : real_total);
        printf("write_size    = %zu (based on intended size, NOT allocated size)\n",
               write_size);
    } else {
        write_size = (size_t)total;
        printf("write_size    = %zu (no overflow, safe)\n", write_size);
    }

    /* Allocate a payload buffer.                                              */
    char *payload = (char *)malloc(write_size);
    if (!payload) { free(buf); perror("malloc payload"); return 1; }
    memset(payload, 'Y', write_size);

    /*
     * [VULNERABLE] memcpy writes `write_size` bytes into a buffer that may
     * be much smaller due to integer overflow.
     */
    memcpy(buf, payload, write_size);

    if (overflowed && write_size > (size_t)total) {
        printf("!! CHAINED VULNERABILITY: Integer overflow -> Heap overflow !!\n");
        printf("   Allocated: %u bytes\n", total);
        printf("   Written:   %zu bytes\n", write_size);
        printf("   Overflow:  %zu bytes past chunk boundary.\n",
               write_size - (size_t)total);
    } else if (overflowed) {
        printf("Integer overflow occurred but write fits the (small) allocation.\n");
    } else {
        printf("No overflow: allocation and write sizes match.\n");
    }

    printf("\n=== Detector Evaluation ===\n");
    if (overflowed) {
        printf("Integer overflow detected in: count * size = %u * %u = %u\n",
               count, size, total);
        printf("A sound detector should chain this to a heap overflow warning.\n");
    } else {
        printf("No integer overflow with these inputs — try larger values.\n");
    }

    free(payload);
    free(buf);
    return 0;
}
