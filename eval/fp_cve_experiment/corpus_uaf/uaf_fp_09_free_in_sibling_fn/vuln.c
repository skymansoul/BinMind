/* 安全: cleanup 释放 p, 但 release 之后无使用. */
#include <stdlib.h>
#include <stdio.h>

void cleanup(char *p) { free(p); }
void touch(char *p) { p[0] = 'T'; }

int main(void) {
    char *p = (char *)malloc(16);
    if (!p) return 1;
    touch(p);
    cleanup(p);
    return 0;
}
