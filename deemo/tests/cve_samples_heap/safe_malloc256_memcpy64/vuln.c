#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// safe_malloc256_memcpy64: Safe case: malloc(256) + memcpy(64) = no overflow
// Type: safe
int main(int argc, char **argv) {
    char src[1024];
    int n = argc > 1 ? atoi(argv[1]) : 128;
    memset(src, 0x41, sizeof(src));
    // Vulnerability: char *buf = malloc(256); memcpy(buf, src, 64); free(buf);
    char *buf = malloc(256); memcpy(buf, src, 64); free(buf);;
    return 0;
}
