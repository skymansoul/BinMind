#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    char *out = (char *)malloc(256);
    if (!out) return 1;
    sprintf(out, argv[1]);        /* 用户格式串 */
    free(out);
    return 0;
}
