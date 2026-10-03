#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * CVE-50: 条件分配溢出 — 条件分支选了较小的分配, 但写入量固定且超限
 *
 * 模式: if(n <= 64) buf=malloc(32); else buf=malloc(128);
 * memcpy(buf, src, 64);  ← when n<=64: alloc=32, write=64 > usable(32)=40 → OVERFLOW
 */
int main() {
    int n = 32;
    char *buf;
    if (n <= 64)
        buf = (char *)malloc(32);
    else
        buf = (char *)malloc(128);
    if (!buf) return 1;
    char src[64];
    memset(src, 'A', 64);
    memcpy(buf, src, 64);
    free(buf);
    return 0;
}
