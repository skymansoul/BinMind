/* 精确边界写入 — offset+size == alloc_size.
 *
 * malloc(64), offset=60, size=4 → 60+4=64 ≤ usable(64)=64 → safe.
 * Expected: TN (boundary-exact → safe, no FP)
 */
#include <stdlib.h>
#include <string.h>

int main() {
    char *buf = (char *)malloc(64);
    if (!buf) return 1;
    /* offset=60 + size=4 = 64, exact boundary → safe */
    memset(buf + 60, 0, 4);
    free(buf);
    return 0;
}
