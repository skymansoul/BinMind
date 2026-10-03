/*
 * FP-06: calloc 零初始化后的安全写入
 *
 * calloc 分配并清零, 后续写入不超出分配范围。
 * 检测器若将 calloc 和 malloc 混为一谈, 可能误报。
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    int *arr = calloc(64, sizeof(int));  // 64*4=256B
    if (!arr) return 1;
    for (int i = 0; i < 64; i++) {
        arr[i] = i;  // 每个写入严格在分配范围内
    }
    printf("calloc array sum: %d\n", arr[0] + arr[63]);
    free(arr);
    return 0;
}
