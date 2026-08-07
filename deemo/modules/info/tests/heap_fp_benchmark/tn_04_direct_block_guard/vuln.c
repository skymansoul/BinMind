/* TN (safe) sample for heap-overflow benchmark */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int main(int argc, char **argv) {
    size_t n = argc > 1 ? (size_t)atoi(argv[1]) : 0;
    char src[128];
    memset(src, 'D', sizeof(src));
    char *buf = (char *)malloc(64);
    if (!buf) return -1;
    if (n <= 64) { memcpy(buf, src, n); }
    free(buf);
    return 0;
}
