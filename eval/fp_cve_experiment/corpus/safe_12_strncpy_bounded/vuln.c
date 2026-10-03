/* 安全: strncpy 长度限制为分配大小. */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    char *buf = (char *)malloc(32);
    if (!buf) return 1;
    strncpy(buf, "hello world", 31);
    buf[31] = 0;
    printf("%s\n", buf);
    free(buf);
    return 0;
}
