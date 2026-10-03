/*
 * BWR-08: read 目标参数修复 (PCST)
 *
 * read(fd, buf, count) 的目标缓冲是第2实参(rsi), 旧逻辑取第1实参(rdi=fd) → 漏报.
 * PCST 修正 dst=idx1, count=idx2: read(fd, p, 64) 写入 malloc(32) → 确认溢出.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    char *p = (char *)malloc(32);
    if (!p) return 1;
    read(0, p, 64);
    printf("%s\n", p);
    free(p);
    return 0;
}
