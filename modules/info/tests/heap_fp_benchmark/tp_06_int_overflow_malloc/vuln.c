/* TP sample for heap-overflow benchmark */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int main(int argc, char **argv) {
    unsigned count = argc > 1 ? (unsigned)atoi(argv[1]) : 0;
    char src[4096];
    memset(src, 'E', sizeof(src));
    char *buf = (char *)malloc(count * 4);
    if (!buf) return -1;
    memcpy(buf, src, sizeof(src));
    free(buf);
    return 0;
}
