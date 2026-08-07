/*
 * GAPSBV-STRESS-02: chunk对齐边界精确测试 — 测试dim4(AllocatorSemantics).
 *
 * malloc(20) → glibc request2size 计算可用大小为 min(32-MINSIZE修正, 对齐).
 * 写入24字节到偏移0 → 有效chunk size≥32B(SIZE_SZ=8时24B可用).
 * 若检测器正确建模ptmalloc2, 24B写入在slack内 → SAFE.
 * 若检测器忽略chunk语义, 24>20 → FP.
 * 期望: SAFE (dim4 chunk模型过滤)
 */
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *buf = (char *)malloc(20);
    if (!buf) return 1;
    memset(buf, 'A', 24);
    free(buf);
    return 0;
}
