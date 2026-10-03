/* safe_same_expr — 安全对照: malloc(s+1) + memcpy(_,_,s) → 证明安全
 * SHIELD size_bound_correlator 应该能证明 s ≤ s+1 恒成立 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    unsigned s = 64;  // 从参数/rbp+0x10 来
    unsigned alloc_sz = s + 1;
    char *buf = (char *)malloc(alloc_sz);
    if (buf) {
        memcpy(buf, "SAFE_DATA_64_BYTES_LONG_STRING_XXXXXXXXXXXXXXXXXXXX", s);
        printf("safe_same_expr: alloc=%u copy=%u (s=%u)\n", alloc_sz, s, s);
        free(buf);
    }
    return 0;
}
