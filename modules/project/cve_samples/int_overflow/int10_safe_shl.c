// int10_safe_shl: 安全左移 — 结果在DWORD范围内
// 模式: 1 << 10 = 1024, 远低于DWORD_MAX
// 预期: 不产生finding (SAFE)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    unsigned int shift = 10;
    if (argc > 1) shift = (unsigned int)atoi(argv[1]);

    // 安全: shift ≤ 12 → 1<<12=4096, 不会溢出
    if (shift > 12) {
        printf("shift too large\n");
        return 1;
    }

    unsigned int alloc_size = 1 << shift;
    char *buf = (char *)malloc(alloc_size);
    if (!buf) return 1;

    memset(buf, 0, alloc_size);
    free(buf);
    return 0;
}
