/* Heap overflow CVE sample — see README.md for details */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    size_t alloc_size = 64;
    if (argc > 1) alloc_size = (size_t)atoi(argv[1]);
    char *buf = (char *)malloc(alloc_size);
    if (!buf) return 1;
    if (argc > 2) {
        size_t write_len = strlen(argv[2]);
        /* BUG: 未检查 write_len <= alloc_size */
        memcpy(buf, argv[2], write_len);
    }
    printf("%s\n", buf);
    free(buf);
    return 0;
}
