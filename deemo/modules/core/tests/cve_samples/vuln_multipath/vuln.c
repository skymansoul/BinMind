/*
 * 多路径堆溢出 — 在 if-else 两条分支上 malloc 大小不同,
 * 但 write 大小不受分支保护约束.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void multipath_copy(int mode, const char *data, size_t len) {
    char *buf;
    if (mode == 0) {
        buf = (char *)malloc(64);
    } else {
        buf = (char *)malloc(128);
    }
    if (!buf) return;
    /* 漏洞: len 可达 256, 两条分支的 alloc 都不够 */
    memcpy(buf, data, len > 256 ? 256 : len);
    printf("mode=%d: %s\n", mode, buf);
    free(buf);
}

int main(void) {
    char d[256];
    memset(d, 'M', sizeof(d));
    d[255] = '\0';
    multipath_copy(0, d, 256);
    multipath_copy(1, d, 256);
    return 0;
}
