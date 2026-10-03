
/* 良性: fprintf 常量格式串到 stderr. */
#include <stdio.h>

int main(int argc, char **argv) {
    fprintf(stderr, "error code: %d\n", argc);
    return 0;
}
