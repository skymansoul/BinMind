/*
 * 递归分配 → 堆溢出 — 在递归调用中逐层减小分配大小,
 * 但最深层的 write 大小固定为大值.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void recursive_write(int depth, const char *data, size_t write_sz) {
    if (depth <= 0) return;
    size_t alloc = (size_t)depth * 32;  /* 越深越小 */
    if (alloc < 16) alloc = 16;

    char *buf = (char *)malloc(alloc);
    if (!buf) return;

    if (depth == 1) {
        /* 最深层: alloc 最小但 write 固定为大值 */
        memcpy(buf, data, write_sz);
        printf("leaf: %s\n", buf);
    } else {
        recursive_write(depth - 1, data, write_sz);
    }
    free(buf);
}

int main(void) {
    char d[256];
    memset(d, 'R', sizeof(d));
    d[255] = '\0';
    recursive_write(4, d, 256);
    return 0;
}
