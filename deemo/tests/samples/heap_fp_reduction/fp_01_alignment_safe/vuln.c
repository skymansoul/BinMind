/*
 * FP-01: 对齐填充安全写入
 *
 * malloc(20) 在 x86_64 glibc 上实际可用 32B (对齐到 16B 边界)。
 * 向偏移 20~31 的写入是安全的, 但若检测器不感知分配器对齐,
 * 会对 store at offset 24 发出误报。
 *
 * 预期: 基准检测器 → 误报 (offset 24 > size 20)
 *       增强管线 → 正确过滤 (effective 32B >= offset 28)
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    char *buf = malloc(20);
    if (!buf) return 1;
    memset(buf, 0, 20);
    // 写入偏移 24, 落在对齐填充区内
    // malloc(20) 在 glibc x86_64 上实际可用空间 = 32B
    *(int *)(buf + 24) = 0x41424344;
    printf("buf[24..27] = 0x%x (expected safe due to alignment)\n",
           *(int *)(buf + 24));
    free(buf);
    return 0;
}
