/*
 * GAPSBV-STRESS-01: 条件限幅 + 嵌套守卫 — 测试dim2(GuardAnalysis) + dim7(PreAllocConstraint).
 *
 * 双重防护: if(size>1024) size=1024; if(size>512) return; malloc(size); memcpy(256).
 * surviving path上 size≤512, 且被cond_cap限制为≤1024.
 * 写入256 ≤ 最小上界512 → 安全.
 * 检测器应判定: SAFE (dim2守卫证明或dim7约束窄化)
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char **argv) {
    int size = (argc > 1) ? atoi(argv[1]) : 256;
    if (size > 1024) size = 1024;
    if (size > 512) return 1;
    char *buf = (char *)malloc(size);
    if (!buf) return 1;
    memcpy(buf, argv[1] ? argv[1] : "test", 256);
    free(buf);
    return 0;
}
