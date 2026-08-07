#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * CVE-44: 指针别名链溢出 — ptr→alias→buf, 写入溢出
 *
 * 模式: buf = malloc(32); char *ptr = buf; char *alias = ptr;
 *       memcpy(alias, src, 128);  // 128 > usable(32)=40 → OVERFLOW
 */
int main() {
    char *buf = (char *)malloc(32);
    if (!buf) return 1;

    char *ptr = buf;
    char *alias = ptr;

    char src[128];
    memset(src, 'Y', 128);
    memcpy(alias, src, 128);

    printf("alias_chain_overflow\n");
    free(buf);
    return 0;
}
