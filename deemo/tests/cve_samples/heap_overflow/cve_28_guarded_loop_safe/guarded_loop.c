/*
 * CVE-28: 受保护循环安全 — 循环边界受guard约束, 写入在分配边界内
 *
 * 模式: malloc(256), for(i<n) buf[i]=x, guard: n<=200
 * 安全: usable(256)=264, loop_write_end=n*1<=200 < 264 → SAFE
 * 无guard分析: n未知 → INCONCLUSIVE
 * 有guard分析: n<=200, write_end=200 < 264 → PROVEN_SAFE
 *
 * 对应: 类似 CVE-2015-7547 (glibc DNS 堆溢出, guard约束循环)
 * 检测预期: PROVEN_SAFE (FM边界推理 + guard约束)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    int n = 200;
    if (argc > 1) n = atoi(argv[1]);
    if (n > 200) n = 200;

    char *buf = (char *)malloc(256);
    if (!buf) return 1;

    int i;
    for (i = 0; i < n; i++) {
        buf[i] = 'G';
    }

    printf("guarded_loop_safe: n=%d\n", n);
    free(buf);
    return 0;
}
