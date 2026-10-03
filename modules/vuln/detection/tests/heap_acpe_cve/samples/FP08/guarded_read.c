
/* 良性: read 长度受分配容量守卫约束. */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static void read_guarded(size_t n) {
    char *buf = (char *)malloc(64);
    if (n > 64) n = 64;
    memset(buf, 0, n);               /* 守卫后写入 */
    free(buf);
}

int main(void) {
    read_guarded(50);
    read_guarded(200);
    return 0;
}
