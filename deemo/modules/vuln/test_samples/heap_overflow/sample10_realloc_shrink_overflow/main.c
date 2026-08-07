/* realloc 缩小后溢出 — 遗留旧 size 引用.
 *
 * p=realloc(p, 32) 缩小, 仍用旧 size=64 写入.
 * Expected: TP (realloc size tracking)
 */
#include <stdlib.h>
#include <string.h>

int main() {
    char *buf = (char *)malloc(64);
    if (!buf) return 1;
    memset(buf, 0, 64);
    /* realloc 缩小到 32 */
    buf = (char *)realloc(buf, 32);
    if (!buf) return 1;
    /* 仍按旧 size=64 写入 → OVERFLOW by 32 bytes */
    memset(buf, 'X', 64);
    free(buf);
    return 0;
}
