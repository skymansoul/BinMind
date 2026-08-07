
/* 良性: memmove 拷贝长度小于分配容量, 且源为更小常量区. */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static void move_small(void) {
    char *dst = (char *)malloc(512);
    char src[32];
    memset(src, 'V', sizeof(src));
    memmove(dst, src, sizeof(src));
    free(dst);
}

int main(void) {
    move_small();
    return 0;
}
