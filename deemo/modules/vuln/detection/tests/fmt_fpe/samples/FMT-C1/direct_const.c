
/* 良性: printf 格式串为直接常量. */
#include <stdio.h>

int main(int argc, char **argv) {
    printf("Hello %s, argc=%d\n", argv[0], argc);
    return 0;
}
