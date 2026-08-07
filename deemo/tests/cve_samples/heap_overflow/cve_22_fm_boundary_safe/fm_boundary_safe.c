/*
 * CVE-22: FM边界推理安全 — 变量偏移有guard约束, 常规证明无法判定
 *
 * 模式: malloc(64), offset=m, guard: m<=56, write 4B
 * 安全: usable(64)=72, write_end=m+4<=60 < 72 → FM边界推理证明SAFE
 * 无FM边界推理时: prove_safe和prove_overflow都返回None → INCONCLUSIVE
 *
 * 对应: 类似 CVE-2022-24834 (Redis SDS 堆溢出, guard约束场景)
 * 检测预期: FM边界推理应判定PROVEN_SAFE
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char *buf = (char *)malloc(64);
    if (!buf) return 1;

    int m = 0;
    if (argc > 1) m = atoi(argv[1]);
    if (m > 56) m = 56;

    *(int *)(buf + m) = 0x42424242;

    printf("fm_boundary_safe: m=%d\n", m);
    free(buf);
    return 0;
}
