/**
 * heap_slack_space - Tests allocator-model awareness (glibc slack space)
 *
 * Under glibc, malloc(20) returns a chunk with a minimum usable size of
 * 24 bytes (or 32 bytes on 64-bit due to alignment). Writing 24 bytes
 * into a 20-byte allocation is therefore safe within the slack space.
 * Writing 40 bytes, however, is a genuine overflow.
 *
 * This test evaluates whether a tool models the actual allocator behavior
 * (distinguishing slack-space "safe" writes from true overflows) or
 * naively flags any write larger than the requested allocation.
 *
 * Compile: gcc -g -O0 -o vuln vuln.c
 * Usage: ./vuln [safe|overflow]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REQUESTED_SIZE 20
#define SLACK_WRITE    24   /* Safe: fits within glibc's minimum chunk size */
#define OVERFLOW_WRITE 40   /* Unsafe: exceeds actual usable space */

int main(int argc, char **argv) {
    char *buf;
    const char *mode;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s [safe|overflow]\n", argv[0]);
        return 1;
    }

    mode = argv[1];

    /* malloc(20): glibc actually gives at least 24-32 bytes of usable space
     * due to minimum chunk size and alignment requirements. */
    buf = (char *)malloc(REQUESTED_SIZE);  // VULN-GUARD: requests 20, glibc gives >=24
    if (!buf) {
        perror("malloc");
        return 1;
    }

    if (strcmp(mode, "safe") == 0) {
        /* SAFE: Writing 24 bytes to a malloc(20) buffer.
         * In glibc, the actual usable space is at least 24 bytes
         * (min chunk size 0x20 - header 0x10 = 0x10 usable on 32-bit,
         *  or 0x20 usable on 64-bit). This is within slack space.
         * A naive tool would flag this; an allocator-aware tool should not. */
        memset(buf, 'A', SLACK_WRITE);  // SAFE-SLACK: 24 bytes fits in glibc min chunk
        printf("Wrote %d bytes into malloc(%d) -- safe (within slack space)\n",
               SLACK_WRITE, REQUESTED_SIZE);

    } else if (strcmp(mode, "overflow") == 0) {
        /* VULNERABLE: Writing 40 bytes to a malloc(20) buffer.
         * Even with glibc slack, 40 bytes exceeds typical minimum chunk
         * usable size and will corrupt adjacent heap data. */
        memset(buf, 'B', OVERFLOW_WRITE);  // VULN: 40 bytes exceeds even slack space
        printf("Wrote %d bytes into malloc(%d) -- overflow (beyond slack space)\n",
               OVERFLOW_WRITE, REQUESTED_SIZE);

    } else {
        fprintf(stderr, "Unknown mode '%s'. Use 'safe' or 'overflow'.\n", mode);
        free(buf);
        return 1;
    }

    free(buf);
    return 0;
}
