#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    char *fmt = (char *)malloc(64);
    if (!fmt) return 1;
    strcpy(fmt, "status=%d\n");   /* 常量内容 */
    printf(fmt, argc);
    free(fmt);
    return 0;
}
