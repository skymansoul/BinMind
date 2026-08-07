/*
 * FP_proof_bounded: False Positive — 写入受变量范围约束保护.
 *
 * GAPSBV S4 (Proof Obligations) 应识别:
 *   1. n 有下界检查 (if n<=0 return → n≥1)
 *   2. n 有上界检查 (if n>256 n=256 → n≤256)
 *   3. malloc(n) 和 memcpy(buf,src,n) 共享同一变量 n
 *   → 写入大小等于分配大小, 且 n∈[1,256] 受约束.
 *
 * 保守分析器产生候选, S4 检测约束并按置信度软降级.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void process_bounded(int n, const char *src) {
    if (n <= 0) return;         /* S4: n ≥ 1 */
    if (n > 256) n = 256;       /* S4: n ≤ 256 */

    char *buf = (char *)malloc(n);
    if (!buf) return;

    memcpy(buf, src, n);        /* alloc=n, write=n → 同变量约束 */

    printf("processed %d bytes\n", n);
    free(buf);
}

int main(void) {
    char data[256];
    memset(data, 'A', sizeof(data));
    process_bounded(128, data);
    return 0;
}
