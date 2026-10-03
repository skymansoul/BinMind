/* 安全: calloc(64,4)=256B, 循环 i<64 写入严格在界内. */
#include <stdlib.h>
#include <stdio.h>

int main(void) {
    int *arr = (int *)calloc(64, sizeof(int));
    if (!arr) return 1;
    for (int i = 0; i < 64; i++) {
        arr[i] = i;
    }
    printf("%d\n", arr[0] + arr[63]);
    free(arr);
    return 0;
}
