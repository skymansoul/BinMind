#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    unsigned n = argc > 1 ? (unsigned)atoi(argv[1]) : 0x40000000;
    int *arr = (int *)malloc(n * sizeof(int));  /* 溢出回绕 */
    if (!arr) return 1;
    for (unsigned i = 0; i < 100; i++) arr[i] = (int)i;  /* 越界写 */
    printf("[*] %d\n", arr[99]);
    free(arr);
    return 0;
}
