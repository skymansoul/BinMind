/* TP sample for heap-overflow benchmark */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int main(int argc, char **argv) {
    size_t n = 0;
    if (argc > 1) n = (size_t)atoi(argv[1]);
    char src[256];
    memset(src, 'A', sizeof(src));
    char *buf = (char *)malloc(64);
    if (!buf) return -1;
    memcpy(buf, src, n);
    free(buf);
    return 0;
}
