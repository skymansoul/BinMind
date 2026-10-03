/* UAF-TP-13: if(len>10) free(p); 随后无条件 p[0] 写入. */
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv) {
    int len = argc > 1 ? 20 : 5;
    char *p = (char *)malloc(32);
    if (!p) return 1;
    if (len > 10) {
        free(p);
    }
    p[0] = 'Q';
    printf("%c\n", p[0]);
    return 0;
}
