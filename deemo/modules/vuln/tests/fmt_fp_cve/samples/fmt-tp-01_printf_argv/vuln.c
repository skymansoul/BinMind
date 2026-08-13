/* 格式串来自 argv, 直接作为 printf 格式. */
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc < 2) return 0;
    printf(argv[1]);
    return 0;
}
