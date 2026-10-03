/* 安全: 大分配小写入, 偏移8远小于4096. */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    char *buf = (char *)malloc(4096);
    if (!buf) return 1;
    memset(buf, 0, 4096);
    buf[8] = 'X';
    printf("%c\n", buf[8]);
    free(buf);
    return 0;
}
