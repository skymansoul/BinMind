#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * CVE-47: 条件分配安全 — guard约束下分配+写入
 *
 * 模式: if (n > 256) n = 256;
 *       buf = malloc(n);
 *       memcpy(buf, src, n);
 * guard: n<=256, memcpy(n) <= usable(256)=264 → SAFE
 */
int main(int argc, char **argv) {
    int n = 128;
    if (argc > 1) n = atoi(argv[1]);

    if (n > 256) n = 256;

    char *buf = (char *)malloc(n);
    if (!buf) return 1;

    char src[256];
    memset(src, 'D', 256);
    memcpy(buf, src, n);

    printf("cond_alloc_safe: n=%d\n", n);
    free(buf);
    return 0;
}
