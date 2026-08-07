/* FMT-TP-03: malloc 缓冲存放用户格式串后 printf. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char *fmt = (char *)malloc(128);
    if (!fmt) return 1;
    strcpy(fmt, argc > 1 ? argv[1] : "stack %n");
    printf(fmt);
    free(fmt);
    return 0;
}
