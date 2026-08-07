/*
 * TN-02: Guard Condition Constrains Write Offset (NO OVERFLOW)
 *
 * malloc(sz) + if (off < sz) guard → 写入在约束范围内
 * Guard条件 ≤ 分配大小 → 可证明安全
 *
 * 正则检测器会误报: 看到buf[offset]即报警
 * LPVRA应判定: SAFE → FILTER (guard constraint使offset < sz)
 */
#include <stdlib.h>

int guarded_write(int sz, int off) {
    char *buf = (char *)malloc(sz);
    if (!buf) return -1;

    if (off < sz) {  /* guard: 保证偏移在分配内 */
        buf[off] = 'G';  /* 安全: 受guard约束 */
    }

    free(buf);
    return 0;
}

int main(void) {
    return guarded_write(128, 64);
}
