/* 安全: a=malloc(32), b=malloc(64), 各自界内写入. */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    char *a = (char *)malloc(32);
    char *b = (char *)malloc(64);
    if (!a || !b) return 1;
    memset(a, 'A', 32);
    memset(b, 'B', 64);
    printf("%c%c\n", a[0], b[63]);
    free(a);
    free(b);
    return 0;
}
