/* 安全: if(flag){free; p=malloc;} p 使用前已被重定义. */
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv) {
    int flag = argc > 1;
    char *p = (char *)malloc(16);
    if (!p) return 1;
    if (flag) {
        free(p);
        p = (char *)malloc(16);
        if (!p) return 1;
    }
    p[0] = 'S';
    printf("%c\n", p[0]);
    free(p);
    return 0;
}
