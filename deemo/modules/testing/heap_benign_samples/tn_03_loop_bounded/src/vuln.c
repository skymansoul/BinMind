#include <stdio.h>
#include <stdlib.h>
int main(void) {
    int *arr = (int *)malloc(100 * sizeof(int));
    if (!arr) return 1;
    for (int i = 0; i < 100; i++) arr[i] = i;   /* 恰为分配范围 */
    printf("[*] %d\n", arr[99]);
    free(arr);
    return 0;
}
