#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    int *arr = (int *)malloc(64 * sizeof(int));
    if (!arr) return 1;
    memset(arr, 0, 64 * sizeof(int));
    printf("[*] %d\n", arr[0]);
    free(arr);
    return 0;
}
