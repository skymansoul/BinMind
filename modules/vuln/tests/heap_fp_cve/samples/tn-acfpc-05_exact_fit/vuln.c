/* TN 对照 5: 精确匹配模式 — malloc(64) + memcpy(p, q, 64).
   写入量与分配量恰等, 双常量数值比较可证安全. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *buf;
    char *src;

    buf = (char *)malloc(64);
    src = (char *)malloc(64);
    if (!buf || !src) {
        return 1;
    }
    memset(src, 'e', 64);
    memcpy(buf, src, 64);
    free(buf);
    free(src);
    return 0;
}
