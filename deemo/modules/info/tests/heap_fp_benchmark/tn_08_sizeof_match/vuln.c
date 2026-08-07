/* TN (safe) sample for heap-overflow benchmark */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int main(int argc, char **argv) {
    size_t n = argc > 1 ? (size_t)atoi(argv[1]) : 16;
    char src[1024];
    memset(src, 'H', sizeof(src));
    int *buf = (int *)malloc(n * sizeof(int));
    if (!buf) return -1;
    memcpy(buf, src, n * sizeof(int));
    free(buf);
    return 0;
}
