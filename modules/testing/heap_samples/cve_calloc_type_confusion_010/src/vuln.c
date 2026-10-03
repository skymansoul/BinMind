/* calloc(n, 4) then memset(n, 0, n*8) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 100;
    int *arr = (int *)calloc(n, sizeof(int));
    if (!arr) return 1;
    memset(arr, 0, n * sizeof(long));  /* BUG: memset more than allocated */
    printf("[*] arr[0]=%d alloc=%zu memset=%zu\n",
           arr[0], n*sizeof(int), n*sizeof(long));
    free(arr);
    return 0;
}
