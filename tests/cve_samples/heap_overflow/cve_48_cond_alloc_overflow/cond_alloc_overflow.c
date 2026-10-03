#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * CVE-48: 条件分配溢出 — guard不足以阻止溢出
 *
 * 模式: if (n > 256) n = 256;
 *       buf = malloc(n);
 *       memcpy(buf, src, 300);  // 300 > usable(256)=264 → OVERFLOW
 * guard约束n但写入大小固定300B, 超过n的最大值
 */
int main(int argc, char **argv) {
    int n = 128;
    if (argc > 1) n = atoi(argv[1]);

    if (n > 256) n = 256;

    char *buf = (char *)malloc(n);
    if (!buf) return 1;

    char src[512];
    memset(src, 'E', 512);
    memcpy(buf, src, 300);

    printf("cond_alloc_overflow: n=%d\n", n);
    free(buf);
    return 0;
}
