
/* 良性: sprintf 格式串为常量. */
#include <stdio.h>

int main(int argc, char **argv) {
    char out[64];
    sprintf(out, "%d", argc);   /* 常量格式串 */
    printf("%s\n", out);
    return 0;
}
