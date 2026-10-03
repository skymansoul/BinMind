/* 多分配指针混淆 — 误将小缓冲区的指针用于大写入.
 *
 * p1=malloc(32), p2=malloc(64), 但 memset 用的是 p1(32) 写入 64 字节.
 * Expected: TP (correct alloc site association)
 */
#include <stdlib.h>
#include <string.h>

int main() {
    char *p1 = (char *)malloc(32);
    char *p2 = (char *)malloc(64);
    if (!p1 || !p2) return 1;
    /* p1 仅 32 字节, 但写入 64 → OVERFLOW (溢出可能覆盖 p2) */
    memset(p1, 'X', 64);
    free(p1);
    free(p2);
    return 0;
}
