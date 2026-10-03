/*
 * CVE-2022-0185 — Linux Kernel Filesystem Heap Overflow Reproduction
 *
 * This sample models the root cause of CVE-2022-0185: a heap buffer
 * overflow where the allocation uses a user-controlled length value,
 * but the write operation uses (length * 2), effectively doubling the
 * amount of data written and overflowing the buffer.
 *
 * The original kernel vulnerability was in the legacy_parse_param()
 * filesystem context code. The guard condition validated `len` but the
 * actual copy used `len * 2`. When `len > buf_size / 2` the product
 * exceeds the allocation, producing a heap overflow.
 *
 * In this reproduction:
 *   - The user supplies a length via argv[1].
 *   - malloc allocates `buf_size` bytes (e.g., 64).
 *   - A guard checks that `len <= MAX_LEN` (e.g., 48).
 *   - The write uses `len * 2` bytes, which can be up to 96.
 *   - When `len * 2 > buf_size` (i.e., len > 32), overflow occurs.
 *
 * Pattern:
 *   buf = malloc(BUF_SIZE);              // 64 bytes
 *   if (len > MAX_LEN) error;           // guards len, not len*2
 *   memcpy(buf, src, (size_t)(len * 2)); // writes up to 96 bytes -> OVERFLOW
 *
 * Usage: ./vuln <length>
 *   length — integer. Values > 32 (up to 48) pass the guard but overflow.
 *
 * VULNERABLE LINE: memcpy(buf, payload, (size_t)(len * 2));
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_SIZE   64
#define MAX_LEN    48     /* len*2 can be 96, exceeding BUF_SIZE (64) when len > 32 */

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <length>\n", argv[0]);
        fprintf(stderr, "  Allocates %d bytes, writes (length * 2) bytes.\n", BUF_SIZE);
        fprintf(stderr, "  length <= %d passes guard, but len*2 > %d overflows when len > 32.\n",
                MAX_LEN, BUF_SIZE);
        return 1;
    }

    int len = atoi(argv[1]);
    int copy_size = len * 2;

    printf("len        = %d\n", len);
    printf("len * 2    = %d\n", copy_size);
    printf("buf_size   = %d\n", BUF_SIZE);
    printf("max allowed = %d\n", MAX_LEN);

    /*
     * [VULNERABLE] Guard condition only checks `len`, not the actual
     * copy size `len * 2`. When len is in [33, 48], the guard passes
     * but the copy writes 66-96 bytes into a 64-byte buffer.
     */
    if (len <= 0 || len > MAX_LEN) {
        fprintf(stderr, "length %d out of range (1..%d)\n", len, MAX_LEN);
        return 1;
    }

    /* Allocation uses the static BUF_SIZE, unaware of the len*2 copy.         */
    char *buf = (char *)malloc(BUF_SIZE);
    if (!buf) { perror("malloc"); return 1; }
    memset(buf, 0xCC, BUF_SIZE);

    /* Prepare a payload large enough for the worst case (len * 2).            */
    char payload[256];
    memset(payload, 'X', sizeof(payload));

    /*
     * [VULNERABLE] memcpy writes (len * 2) bytes, doubling the user-supplied
     * value. The guard only checked `len`, not `len * 2`. When len > 32,
     * the copy overflows the 64-byte buffer.
     */
    memcpy(buf, payload, (size_t)(len * 2));

    printf("buf[0..15]  = %.16s\n", buf);

    if (copy_size <= BUF_SIZE) {
        printf("buf[16..%d] = %.16s  (safe, copy <= %d)\n",
               copy_size - 1, buf + 16, BUF_SIZE);
    } else {
        printf("buf[16..31] = %.16s  <-- overflow region\n", buf + 16);
        printf("buf[32..47] = %.16s  <-- overflow region\n", buf + 32);
        printf("buf[48..63] = %.16s  <-- overflow region\n", buf + 48);
        printf("buf[64..79] = %.16s  <-- beyond chunk boundary!\n", buf + 64);
        printf("!! HEAP OVERFLOW: wrote %d bytes into %d-byte buffer !!\n",
               copy_size, BUF_SIZE);
    }

    free(buf);
    return 0;
}
