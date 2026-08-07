/* 正确守卫的写入 — 有有效的边界检查.
 *
 * malloc(64), 写入前检查 idx < 64 → 安全.
 * Expected: TN (guarded correctly → safe, no FP)
 */
#include <stdlib.h>
#include <string.h>

int main() {
    unsigned char *buf = (unsigned char *)malloc(64);
    if (!buf) return 1;
    int idx = 63;
    if (idx < 64) {  /* 守卫条件正确 */
        buf[idx] = 'X';  /* safe: idx=63 < alloc=64 */
    }
    free(buf);
    return 0;
}
