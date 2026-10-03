#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * CVE-43: 指针别名链安全 — ptr→alias→buf, 多层别名
 *
 * 模式: buf = malloc(64); char *ptr = buf; char *alias = ptr;
 *       memcpy(alias, src, 56);  // 56 <= usable(64)=72 → SAFE
 * 别名追踪: alias→ptr→buf, 需要追踪两层别名链
 */
int main() {
    char *buf = (char *)malloc(64);
    if (!buf) return 1;

    char *ptr = buf;
    char *alias = ptr;

    char src[64];
    memset(src, 'X', 64);
    memcpy(alias, src, 56);

    printf("alias_chain_safe\n");
    free(buf);
    return 0;
}
