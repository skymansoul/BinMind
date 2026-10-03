/* TP sample for heap-overflow benchmark */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int main(int argc, char **argv) {
    size_t n = argc > 1 ? (size_t)atoi(argv[1]) : 0;
    char src[2048];
    memset(src, 'G', sizeof(src));
    char *buf = (char *)calloc(n, 8);
    if (!buf) return -1;
    memcpy(buf, src, sizeof(src));
    free(buf);
    return 0;
}
