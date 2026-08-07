/* TP sample for heap-overflow benchmark */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int main(int argc, char **argv) {
    int flag = argc > 1 ? atoi(argv[1]) : 0;
    char src[128];
    memset(src, 'K', sizeof(src));
    char *buf = (char *)malloc(64);
    if (!buf) return -1;
    if (flag) { memcpy(buf, src, 128); }
    free(buf);
    return 0;
}
