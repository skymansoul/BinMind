/* 守卫不充分的堆溢出 — 边界检查写的是 ≤ 而非 <.
 *
 * cmp rcx, 64; ja → overflow → 但循环边界检查用 ≤ 64,
 * 第64次迭代写入 idx=63: offset=63*8+8=512 > alloc=512 → 恰好溢出.
 * Expected: TP (守卫存在但不足以防止溢出)
 */
#include <stdlib.h>
#include <string.h>

int main() {
    unsigned long long *buf = (unsigned long long *)malloc(512);
    if (!buf) return 1;
    /* 守卫: idx <= 64, 但 64*8=512, idx=63 时写 63*8..63*8+8=512 → 越界 */
    for (int idx = 0; idx <= 64; idx++) {
        buf[idx] = (unsigned long long)idx;  /* idx=64: overflow by 8 */
    }
    free(buf);
    return 0;
}
