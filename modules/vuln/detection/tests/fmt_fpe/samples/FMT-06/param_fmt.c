
/* 格式串经函数参数传递 — 调用方可控. */
#include <stdio.h>

static void emit(const char *fmt, int v) {
    printf(fmt, v);          /* fmt 来自参数 */
}

int main(int argc, char **argv) {
    emit(argv[1], argc);
    return 0;
}
