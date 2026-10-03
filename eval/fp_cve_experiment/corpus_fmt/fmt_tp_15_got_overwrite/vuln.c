/* FMT-TP-15: sprintf(user_fmt) 中 %n 写已释放/可写区域. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    char out[32];
    char *fmt = (char *)malloc(64);
    if (!fmt) return 1;
    strcpy(fmt, argc > 1 ? argv[1] : "%n");
    sprintf(out, fmt);
    free(fmt);
    printf("%s\n", out);
    return 0;
}
