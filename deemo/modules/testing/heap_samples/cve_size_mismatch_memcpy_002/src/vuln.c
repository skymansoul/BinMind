/* Alloc fixed size, copy variable size => overflow when size > alloc */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define FIXED_BUF 1024
int main(int argc, char **argv) {
    unsigned char *buf = (unsigned char *)malloc(FIXED_BUF);
    if (!buf) return 1;
    size_t len = argc > 1 ? strlen(argv[1]) : 0;
    memcpy(buf, argv[1], len);  /* BUG: len can exceed FIXED_BUF */
    printf("[*] copied %zu bytes\n", len);
    free(buf);
    return 0;
}
