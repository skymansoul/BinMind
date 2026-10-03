/*
 * BWR-01: strcpy 字面量溢出
 *
 * 无界写入 strcpy 的目标为 malloc(4) 的堆缓冲区,
 * 源为 .rodata 字符串字面量 (40字符+NUL=41字节 > glibc chunk可用区 24B).
 * BWR 从源字面量恢复写尺寸上界 → 确认溢出.
 * 基线(跳过无界写)会漏报.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *p = (char *)malloc(4);
    if (!p) return 1;
    strcpy(p, "THIS-IS-A-VERY-LONG-STRING-STRING-STRING-STRING");
    printf("%s\n", p);
    free(p);
    return 0;
}
