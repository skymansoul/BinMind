/**
 * heap_no_guard_check - Heap buffer allocated with user-controlled size,
 *                       memcpy without any bounds guard.
 *
 * This is a straightforward true positive: the user supplies the allocation
 * size and the same size is used for memcpy, but there is NO validation
 * that the source buffer fits within the destination. A static analyzer
 * should flag the absence of a guard check on user_size.
 *
 * Compile: gcc -g -O0 -o vuln vuln.c
 * Usage: ./vuln <size> <source_string>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    size_t user_size;
    char *buf;
    const char *src;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <size> <string>\n", argv[0]);
        return 1;
    }

    user_size = (size_t)atoi(argv[1]);
    src = argv[2];

    if (user_size == 0 || user_size > 65536) {
        fprintf(stderr, "Size must be between 1 and 65536\n");
        return 1;
    }

    /* Allocate user_size bytes -- no guard on whether this is enough
     * for the source data. The size comes directly from user input. */
    buf = (char *)malloc(user_size);  // VULN-GUARD: alloc based on untrusted input
    if (!buf) {
        perror("malloc");
        return 1;
    }

    /* VULNERABLE: memcpy uses the user-supplied size directly with no
     * check against strlen(src). If user_size > strlen(src), it reads
     * past src. If user_size < actual data size needed, we overflow buf.
     * A safe implementation would compute the needed size and validate. */
    memcpy(buf, src, user_size);  // VULN: no bounds check, user_size is untrusted

    printf("Copied %zu bytes from source to heap buffer\n", user_size);

    free(buf);
    return 0;
}
