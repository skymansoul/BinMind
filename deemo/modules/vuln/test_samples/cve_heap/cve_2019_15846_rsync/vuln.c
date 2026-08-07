/* CVE-2019-15846 — rsync 整数溢出 → 堆越界 (calloc 乘积)。
 * 分配 n, 写入 2n。
 * Expected: TP */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char **argv) {
    size_t n = 32;
    if (argc > 1) n = (size_t)atoi(argv[1]);
    char *buf = (char *)calloc(n, 1);
    if (!buf) return 1;
    char src[128];
    memset(src, 'C', sizeof(src));
    memcpy(buf, src, n * 2);              /* 2 倍越界 */
    free(buf);
    return 0;
}
