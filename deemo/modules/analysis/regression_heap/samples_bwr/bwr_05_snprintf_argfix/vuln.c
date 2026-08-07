/*
 * BWR-05: snprintf 参数索引修复 (PCST)
 *
 * snprintf(dst, size, fmt) 的 size 是第2实参(rsi), 旧逻辑统一取第3实参(rdx=fmt指针),
 * 导致错误数据流. PCST 按函数签名提取 size=40 > malloc(8) chunk 32B → 确认溢出.
 */
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    char *p = (char *)malloc(8);
    if (!p) return 1;
    snprintf(p, 40, "abcdefghijklmnopqrstuvwxyz0123456789abcdef");
    printf("%s\n", p);
    free(p);
    return 0;
}
