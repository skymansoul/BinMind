#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// safe_realloc_then_memcpy: Safe: realloc to fit + memcpy
// Type: safe
int main(int argc, char **argv) {
    char src[1024];
    int n = argc > 1 ? atoi(argv[1]) : 128;
    memset(src, 0x41, sizeof(src));
    // Vulnerability: char *buf = malloc(32); buf = realloc(buf, 256); memcpy(buf, src, 128); free(buf);
    char *buf = malloc(32); buf = realloc(buf, 256); memcpy(buf, src, 128); free(buf);;
    return 0;
}
