/* TN 对照 2: 守卫支配模式 — malloc(256); if (n <= 256) memcpy(p, q, n).
   写入量受前置边界检查约束, 不可能越界. 无 CFG 的模式匹配工具
   无法区分分支, 报 FP; ACFPC 守卫链证明上界 ≤ 可用大小后压制. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    size_t n;
    char *buf;
    char *src;

    if (argc < 2) {
        return 0;
    }
    n = strlen(argv[1]);
    buf = (char *)malloc(256);
    src = (char *)malloc(n);
    if (!buf || !src) {
        return 1;
    }
    if (n <= 256) {
        memcpy(src, argv[1], n);
        memcpy(buf, src, n);
    }
    free(buf);
    free(src);
    return 0;
}
