#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    unsigned n = argc > 1 ? (unsigned)atoi(argv[1]) : 0x10000000;
    size_t sz = (size_t)n * 4;
    if (sz > 0x100000000ULL) return 1;  /* 上界 4G, 无效检查 */
    char *buf = (char *)malloc(sz);
    if (!buf) return 1;
    memset(buf, 0, 0x1000);             /* 写入超分配 */
    free(buf);
    return 0;
}
