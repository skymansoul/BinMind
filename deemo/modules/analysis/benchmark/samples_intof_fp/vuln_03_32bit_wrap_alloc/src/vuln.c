#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    unsigned n = argc > 1 ? (unsigned)atoi(argv[1]) : 0x100000;
    int *arr = (int *)malloc((size_t)(n * 8));  /* 32 位回绕 */
    if (!arr) return 1;
    for (unsigned i = 0; i < 1000; i++) arr[i] = (int)i;
    printf("[*] %d\n", arr[999]);
    free(arr);
    return 0;
}
