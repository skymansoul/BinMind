/* 安全: alloc对齐后有效容量 ≥ write
 * 预期: 检测器应通过分配器语义过滤 — 对齐空间吸收溢出
 */
#include <stdlib.h>
#include <string.h>

int main() {
    char *p = (char*)malloc(60);
    /* alloc=60, 对齐后有效容量=64 (x86_64: 60→80→64有效)
     * 注意: 实际对齐语义下60→76→64仍安全 */
    memcpy(p, "short", 5);
    free(p);
    return 0;
}
