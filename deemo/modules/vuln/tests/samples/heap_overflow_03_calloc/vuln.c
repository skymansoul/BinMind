/* heap_overflow_03 — calloc 数组越界
 *
 * calloc(nmemb, size) 分配 nmemb*size 字节.
 * 漏洞: 循环索引使用 nmemb 而非实际分配的元素数,
 *       或 calloc 的 nmemb*size 计算溢出后被截断.
 */
#include <stdio.h>
#include <stdlib.h>

#define NELEM 16

int main(void) {
    /* calloc 分配 16 个 int (64 bytes) */
    int *arr = (int *)calloc(NELEM, sizeof(int));
    if (!arr) return 1;

    /* BUG: 循环写入 32 个 int → 128 bytes → 越界 64 bytes */
    for (int i = 0; i < NELEM * 2; i++) {
        arr[i] = i * 10;
    }

    printf("arr[%d] = %d\n", NELEM * 2 - 1, arr[NELEM * 2 - 1]);
    free(arr);
    return 0;
}
