/*
 * HEAP-OVERFLOW-LOOP-02: 循环写越界 —— 循环边界错误导致堆溢出。
 *
 * 模式: for(i=0; i<=n; i++) 写 n 个元素时多写一个。
 * malloc(n * sizeof(int)), 但循环写成 i<=n 导致写 n+1 个元素。
 * 这是真实的 off-by-one 堆溢出, 在静态分析中常被漏报（因区间分析
 * 难以精确推断 i 的终值）。
 *
 * 误报分析: 简单正则匹配看到 malloc(n*4) + 循环写 → 可能误报
 * 精确区间分析: 循环归纳变量 i ∈ [0, n] → 最大偏移 (n+1)*4 > n*4 → 真阳性
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    /* 从命令行获取数组大小, 默认 10 */
    int n = 10;
    if (argc > 1) n = atoi(argv[1]);
    if (n <= 0) n = 10;
    if (n > 10000) n = 10000;  /* 约束: n <= 10000 */

    /* 分配 n 个 int */
    int *buf = (int *)malloc(n * sizeof(int));
    if (!buf) { perror("malloc"); return 1; }

    /*
     * VULN: 循环条件是 i <= n, 而 buf 只有 n 个元素 (索引 0..n-1)
     * 当 i=n 时写入 buf[n], 溢出 4 字节
     */
    for (int i = 0; i <= n; i++) {  /* <-- OFF-BY-ONE: 应为 i < n */
        buf[i] = i;
    }

    printf("last elem: %d\n", buf[n-1]);
    free(buf);
    return 0;
}
