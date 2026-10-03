/*
 * TN-03: calloc With Correct Usage (NO OVERFLOW)
 *
 * calloc(nmemb=64, size=4) → 分配256B
 * memset写入128B → 远小于分配 → 无溢出
 *
 * 正则检测器可能误报: memset大小未关联alloc大小
 * LPVRA应判定: SAFE → FILTER (write_size=128 < alloc_lo=256)
 */
#include <stdlib.h>
#include <string.h>

int calloc_correct_use(void) {
    int *arr = (int *)calloc(64, sizeof(int));  /* 64*4 = 256B */
    if (!arr) return -1;

    /* 只初始化前半部分 */
    memset(arr, 0x00, 128);  /* 256分配, 128写入 → 安全 */

    free(arr);
    return 0;
}

int main(void) {
    return calloc_correct_use();
}
