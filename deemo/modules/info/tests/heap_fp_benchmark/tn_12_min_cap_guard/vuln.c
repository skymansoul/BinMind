/* TN (safe) sample for heap-overflow benchmark */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
static size_t _min(size_t a, size_t b) { return a < b ? a : b; }
int main(int argc, char **argv) {
    size_t n = argc > 1 ? (size_t)atoi(argv[1]) : 0;
    char src[1024];
    memset(src, 'K', sizeof(src));
    char *buf = (char *)malloc(64);
    if (!buf) return -1;
    memcpy(buf, src, _min(n, 64));
    free(buf);
    return 0;
}
