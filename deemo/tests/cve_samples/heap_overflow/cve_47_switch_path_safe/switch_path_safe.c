#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * CVE-47: switch路径安全 — 每个case写入量均在分配范围内
 *
 * 模式: malloc(100); switch(flag) {
 *   case 1: memcpy(buf, a, 50); break;
 *   case 2: memcpy(buf, b, 80); break;
 *   default: memcpy(buf, c, 40);
 * }
 * usable(100)=104, 最大写入80 <= 104 → SAFE
 */
int main() {
    int flag = 2;
    char *buf = (char *)malloc(100);
    if (!buf) return 1;
    char a[64], b[96], c[64];
    memset(a, 'X', 50);
    memset(b, 'Y', 80);
    memset(c, 'Z', 40);
    switch (flag) {
        case 1: memcpy(buf, a, 50); break;
        case 2: memcpy(buf, b, 80); break;
        default: memcpy(buf, c, 40); break;
    }
    free(buf);
    return 0;
}
