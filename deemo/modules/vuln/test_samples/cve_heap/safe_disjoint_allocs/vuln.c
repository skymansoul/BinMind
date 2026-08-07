/* safe_disjoint_allocs — 多分配点指针混淆 (TN)。
 * buf1(64) 写 64, buf2(32) 写 32, 均安全。
 * Expected: TN */
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *buf1 = (char *)malloc(64);
    char *buf2 = (char *)malloc(32);
    if (!buf1 || !buf2) return 1;
    memset(buf1, 'G', 64);                /* 恰达 buf1 边界 */
    memset(buf2, 'H', 32);                /* 恰达 buf2 边界 */
    free(buf1);
    free(buf2);
    return 0;
}
