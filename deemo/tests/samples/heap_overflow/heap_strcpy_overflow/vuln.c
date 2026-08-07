/**
 * heap_strcpy_overflow - Classic strcpy-based heap overflow
 *
 * malloc(8) followed by strcpy of a user-supplied string (from argv).
 * strcpy has no bounds checking -- if the input exceeds 7 characters
 * (plus null terminator), the heap buffer overflows. This tests whether
 * a tool understands strcpy semantics and can track the relationship
 * between allocation size and string length.
 *
 * Compile: gcc -g -O0 -o vuln vuln.c
 * Usage: ./vuln <string>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_SIZE 8

int main(int argc, char **argv) {
    char *buf;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <string>\n", argv[0]);
        fprintf(stderr, "  (Try a string longer than %d characters)\n", BUF_SIZE - 1);
        return 1;
    }

    /* Allocate only 8 bytes on the heap */
    buf = (char *)malloc(BUF_SIZE);  // VULN-GUARD: only 8 bytes allocated
    if (!buf) {
        perror("malloc");
        return 1;
    }

    /* VULNERABLE: strcpy copies argv[1] (including null terminator) into
     * an 8-byte buffer with no bounds checking. If the input is longer
     * than 7 characters, the null terminates buffer overflow.
     * strcpy is inherently unsafe and should be flagged regardless of
     * the specific input length. */
    strcpy(buf, argv[1]);  // VULN: unbounded strcpy into 8-byte heap buffer

    printf("Buffer contents: '%s' (may be truncated/corrupted)\n", buf);

    free(buf);
    return 0;
}
