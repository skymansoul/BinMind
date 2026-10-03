/* 安全: idx 受守卫 idx<64 约束后写入. */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    char *buf = (char *)malloc(64);
    if (!buf) return 1;
    int idx = 1000;
    if (idx < 64 && idx >= 0) {
        buf[idx] = 'G';
    }
    printf("%c\n", buf[0]);
    free(buf);
    return 0;
}
