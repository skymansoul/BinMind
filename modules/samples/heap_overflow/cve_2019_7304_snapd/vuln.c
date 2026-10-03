/*
 * CVE-2019-7304 模式复刻 — snapd 符号链接处理堆溢出
 * 真实漏洞: snapd 经典模式安装时通过符号链接实现权限提升,
 *           核心是路径拼接缓冲的越界写 (CVE-2019-7304)
 * 触发条件: 路径分量总长度超过分配缓冲
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BASE_LEN 48

char *join_path(const char *base, const char *rel) {
    size_t blen = strlen(base);
    size_t rlen = strlen(rel);
    char *out = (char *)malloc(BASE_LEN);   /* 固定 48B */
    if (!out) return NULL;
    memcpy(out, base, blen);
    out[blen] = '/';                        /* 写至 blen+1 */
    memcpy(out + blen + 1, rel, rlen);
    out[blen + 1 + rlen] = 0;               /* 写终点 blen+2+rlen */
    return out;
}

int main(int argc, char **argv) {
    /* base 30 + rel 40 = 71 > 48 缓冲 */
    char base[40], rel[64];
    memset(base, 'B', 30); base[30] = 0;
    memset(rel, 'R', 40); rel[40] = 0;
    char *p = join_path(base, rel);         /* 71B 写 48B 缓冲 */
    if (p) free(p);
    return 0;
}
