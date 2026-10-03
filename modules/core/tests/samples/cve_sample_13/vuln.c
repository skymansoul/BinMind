/* 分配器约束测试: malloc(5) 实际分配 16B, memcpy 写 8B 不溢出
 * 测试 alloc_constraints.py 是否正确处理 glibc 对齐行为 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void tiny_alloc(void) {
    char *buf = (char *)malloc(5); /* glibc: actual usable = 16 - 8 = 8 on x86 */
    if (!buf) return;
    /* 写 8B ≤ 可用 8B → 不应报告溢出 */
    memcpy(buf, "12345678", 8);
    printf("%.8s\n", buf);
    free(buf);
}

int main(void) {
    tiny_alloc();
    return 0;
}
