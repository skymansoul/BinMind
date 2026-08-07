/* safe_alloc_controllable — 分配与写入同源 (TN)。
 * memcpy 写入量与 malloc 大小相同变量 n。
 * Expected: TN */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static void copy_n(size_t n, char *dst, const char *src) {
    char *buf = (char *)malloc(n);
    if (!buf) return;
    memcpy(buf, src, n);                  /* 同源 → 安全 */
    free(buf);
    (void)dst;
}

int main(int argc, char **argv) {
    size_t n = 48;
    if (argc > 1) n = strlen(argv[1]);
    copy_n(n, argv[2], argv[3]);
    return 0;
}
