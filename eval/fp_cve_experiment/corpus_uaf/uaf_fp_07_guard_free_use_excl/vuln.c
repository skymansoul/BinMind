/* 安全: if(flag){free}else{use} 经同一守卫互斥. */
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv) {
    int flag = argc > 1;
    char *p = (char *)malloc(16);
    if (!p) return 1;
    if (flag) {
        free(p);
    } else {
        p[0] = 'S';
        printf("%c\n", p[0]);
        free(p);
    }
    return 0;
}
