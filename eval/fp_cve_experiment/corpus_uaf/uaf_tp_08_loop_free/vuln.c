/* UAF-TP-08: for 循环内 free(p), 循环后 p[0] 使用. */
#include <stdlib.h>
#include <stdio.h>

int main(void) {
    char *p = (char *)malloc(16);
    if (!p) return 1;
    for (int i = 0; i < 3; i++) {
        if (i == 2) free(p);
    }
    p[0] = 'L';
    printf("%c\n", p[0]);
    return 0;
}
