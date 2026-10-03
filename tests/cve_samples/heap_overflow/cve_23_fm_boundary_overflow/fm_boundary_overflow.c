/*
 * CVE-23: FM边界推理溢出 — 变量偏移有guard下界约束, 证明必然溢出
 *
 * 模式: malloc(32), offset=m, guard: m>=40, write 4B
 * 溢出: usable(32)=40, write_end=m+4>=44 > 40 → FM边界推理证明OVERFLOW
 * 无FM边界推理时: prove_safe假设m+4<=40, 但m>=40→m+4>=44>40→矛盾→OVERFLOW
 *                 prove_overflow假设m+4<=40, m>=40→44<=40→矛盾→也能判定
 *
 * 对应: 类似 CVE-2020-10713 (GRUB2 堆溢出)
 * 检测预期: PROVEN_OVERFLOW
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char *buf = (char *)malloc(32);
    if (!buf) return 1;

    int m = 40;
    if (argc > 1) m = atoi(argv[1]);
    if (m < 40) m = 40;

    *(int *)(buf + m) = 0x43434343;

    printf("fm_boundary_overflow: m=%d\n", m);
    free(buf);
    return 0;
}
