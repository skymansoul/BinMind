/*
 * BWR-04: sprintf 宽度字段溢出
 *
 * 目标 malloc(4), 格式串 "%40s!" 源自 .rodata,
 * 宽度字段给出最大输出 = 40 + 1(感叹号) + 1(NUL) = 42 > glibc chunk 32B.
 * BWR 解析格式串宽度字段, 确认溢出.
 */
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    char *p = (char *)malloc(4);
    if (!p) return 1;
    sprintf(p, "%40s!", "hi");
    printf("%s\n", p);
    free(p);
    return 0;
}
