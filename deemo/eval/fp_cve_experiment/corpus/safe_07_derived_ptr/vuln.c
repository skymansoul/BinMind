/* 安全: p=buf+32, memset(p,32) 覆盖 buf[32..63], 在malloc(64)内. */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    char *buf = (char *)malloc(64);
    if (!buf) return 1;
    memset(buf, 0, 64);
    char *p = buf + 32;
    memset(p, 'X', 32);
    printf("%c%c\n", buf[32], buf[63]);
    free(buf);
    return 0;
}
