/* 安全: buf→p→q 别名链, memset(q+64,32) 在128B内. */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    char *buf = (char *)malloc(128);
    if (!buf) return 1;
    char *p = buf;
    char *q = p;
    memset(q + 64, 'Y', 32);
    printf("%c%c\n", q[64], q[95]);
    free(buf);
    return 0;
}
