#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * CVE-48: switch路径溢出 — 某个case的写入超出分配范围
 *
 * 模式: malloc(64); switch(flag) {
 *   case 1: memcpy(buf, a, 32); break;
 *   case 2: memcpy(buf, b, 96); break;  ← 96 > usable(64)=72
 * }
 */
int main() {
    int flag = 2;
    char *buf = (char *)malloc(64);
    if (!buf) return 1;
    char a[64], b[128];
    memset(a, 'X', 32);
    memset(b, 'Y', 96);
    switch (flag) {
        case 1: memcpy(buf, a, 32); break;
        case 2: memcpy(buf, b, 96); break;
        default: break;
    }
    free(buf);
    return 0;
}
