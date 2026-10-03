/* Alloc n bytes, write n ints (4x the allocation) */
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    size_t n = argc > 1 ? (size_t)atoi(argv[1]) : 8;
    char *buf = (char *)malloc(n);
    if (!buf) return 1;
    int *ip = (int *)buf;
    for (size_t i = 0; i < n; i++) ip[i] = (int)i;  /* BUG: writes n*4 bytes */
    printf("[*] last=%d\n", ip[n-1]);
    free(buf);
    return 0;
}
