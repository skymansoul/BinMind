
/* 良性: 静态全局常量数组作格式串. */
#include <stdio.h>

static const char g_fmt[] = "result: %d\n";

int main(int argc, char **argv) {
    printf(g_fmt, argc);
    return 0;
}
