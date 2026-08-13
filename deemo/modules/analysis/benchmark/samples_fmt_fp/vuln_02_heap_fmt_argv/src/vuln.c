#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    char *fmt = (char *)malloc(strlen(argv[1]) + 1);
    if (!fmt) return 1;
    strcpy(fmt, argv[1]);         /* 用户输入进堆 */
    printf(fmt);
    free(fmt);
    return 0;
}
