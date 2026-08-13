/* 安全: realloc(ptr, 64) 缩小, 之后按64字节访问. */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    char *buf = (char *)malloc(256);
    if (!buf) return 1;
    memset(buf, 'A', 256);
    buf = (char *)realloc(buf, 64);
    if (!buf) return 1;
    memset(buf, 'B', 64);
    printf("%.64s\n", buf);
    free(buf);
    return 0;
}
