#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    unsigned n = argc > 1 ? (unsigned)atoi(argv[1]) : 16;
    size_t sz = (size_t)n * sizeof(int);
    if (sz > 0x100000) return 1;       /* 正确检查 */
    int *arr = (int *)malloc(sz);
    if (!arr) return 1;
    memset(arr, 0, sz);
    free(arr);
    return 0;
}
