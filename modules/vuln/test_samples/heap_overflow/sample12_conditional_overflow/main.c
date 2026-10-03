/* 条件路径溢出 — 仅在特定分支溢出.
 *
 * alloc=64, safe 分支正常, unsafe 分支写入 128.
 * Expected: TP (path-sensitive detection)
 */
#include <stdlib.h>
#include <string.h>

int main() {
    int safe_mode = 0;  /* 0=unsafe path */
    char *buf = (char *)malloc(64);
    if (!buf) return 1;
    if (safe_mode) {
        memset(buf, 0, 32);   /* safe: 32 < 64 */
    } else {
        memset(buf, 0, 128);  /* OVERFLOW: 128 > 64 */
    }
    free(buf);
    return 0;
}
