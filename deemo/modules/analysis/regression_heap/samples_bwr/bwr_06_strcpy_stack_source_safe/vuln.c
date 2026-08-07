/*
 * BWR-06: strcpy 栈缓冲区源安全
 *
 * 源为栈缓冲区 char tmp[16] (经 fgets 填满), 目标 malloc(32).
 * BWR 通过 lea [rbp-X] 恢复源上界 16 ≤ 可用区 32 → 安全.
 * 基线(跳过无界写)不会误报; 本样本验证 BWR 不上报.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char tmp[16];
    char *p = (char *)malloc(32);
    if (!p) return 1;
    fgets(tmp, sizeof(tmp), stdin);
    tmp[15] = 0;
    strcpy(p, tmp);
    printf("%s\n", p);
    free(p);
    return 0;
}
