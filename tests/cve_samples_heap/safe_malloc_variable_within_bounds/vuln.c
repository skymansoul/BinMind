#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// safe_malloc_variable_within_bounds: Safe: malloc(N) + memcpy(src, min(len, N)) = guarded copy
// Type: safe
int main(int argc, char **argv) {
    char src[1024];
    int n = argc > 1 ? atoi(argv[1]) : 128;
    memset(src, 0x41, sizeof(src));
    // Vulnerability: char *buf = malloc(n); memcpy(buf, src, n > 64 ? 64 : n); free(buf);
    char *buf = malloc(n); memcpy(buf, src, n > 64 ? 64 : n); free(buf);;
    return 0;
}
