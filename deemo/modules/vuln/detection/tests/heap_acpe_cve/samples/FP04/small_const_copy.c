
/* 良性: 远小于容量的常数拷贝. */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static void small_copy(void) {
    char *dst = (char *)malloc(256);
    memcpy(dst, "small", 6);
    free(dst);
}

int main(void) {
    small_copy();
    return 0;
}
