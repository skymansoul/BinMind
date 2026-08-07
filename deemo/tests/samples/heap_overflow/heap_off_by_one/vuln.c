/**
 * heap_off_by_one - Classic off-by-one heap overflow via null byte
 *
 * malloc(strlen(str)) allocates space for the characters only,
 * but strcpy copies strlen(str) + 1 bytes (including the null
 * terminator). This overflows the heap buffer by exactly one byte
 * (the '\0' terminator), which can corrupt adjacent heap metadata.
 *
 * Compile: gcc -g -O0 -o vuln vuln.c
 * Usage: ./vuln <string>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char *buf;
    const char *input;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <string>\n", argv[0]);
        return 1;
    }

    input = argv[1];

    /* VULNERABLE: allocates strlen(input) bytes, but strcpy needs
     * strlen(input) + 1 bytes for the null terminator.
     * The allocation misses the +1 for '\0'. */
    buf = (char *)malloc(strlen(input));  // VULN: missing +1 for null terminator

    if (!buf) {
        perror("malloc");
        return 1;
    }

    /* VULNERABLE: strcpy writes strlen(input) + 1 bytes into a buffer
     * that only has room for strlen(input) bytes. The null byte overflows
     * by one, potentially corrupting heap chunk metadata. */
    strcpy(buf, input);  // VULN: off-by-one overflow (null terminator)

    printf("Copied string '%s' (%zu bytes + null) into a buffer of %zu bytes\n",
           buf, strlen(input), strlen(input));

    free(buf);
    return 0;
}
