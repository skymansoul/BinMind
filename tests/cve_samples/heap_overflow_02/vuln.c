/* heap_overflow_02 — calloc(32) 后在循环中越界写入
 * 对应 CWE-122: 循环边界错误导致堆溢出
 * 编译: gcc -o vuln vuln.c
 */
#include <stdio.h>
#include <stdlib.h>

void process(int n) {
    int *arr = (int *)calloc(8, sizeof(int));  /* 8 个 int, 32 字节 */
    if (!arr) return;
    for (int i = 0; i <= n; i++) {  /* 越界: i==8 时写 arr[8] */
        arr[i] = i * 10;
    }
    printf("last: %d\n", arr[n]);
    free(arr);
}

int main(int argc, char **argv) {
    int n = 8;
    if (argc >= 2) n = atoi(argv[1]);
    process(n);
    return 0;
}
