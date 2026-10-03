#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * CVE-49: 条件分配安全 — 根据条件选择不同大小的分配, 全部满足写入需求
 *
 * 模式: if(n <= 64) buf=malloc(64); else buf=malloc(128);
 * memcpy(buf, src, 64);  ← 64 <= usable(64)=72 → SAFE
 */
int main() {
    int n = 100;
    char *buf;
    if (n <= 64)
        buf = (char *)malloc(64);
    else
        buf = (char *)malloc(128);
    if (!buf) return 1;
    char src[64];
    memset(src, 'A', 64);
    memcpy(buf, src, 64);
    free(buf);
    return 0;
}
