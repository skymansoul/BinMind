/* heap_overflow_04 — calloc 分配后多字节越界写
 * 对应 CWE-122: calloc 数组越界
 * 编译: gcc -o vuln vuln.c
 */
#include <stdio.h>
#include <stdlib.h>

int main() {
    int *arr = (int *)calloc(4, sizeof(int));  /* 4 个 int */
    for (int i = 0; i < 10; i++)
        arr[i] = i;  /* i>=4 时越界 */
    free(arr);
    return 0;
}
