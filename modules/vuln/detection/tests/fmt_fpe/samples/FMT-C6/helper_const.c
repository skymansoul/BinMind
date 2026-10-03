
/* 良性: 常量格式串经辅助函数间接传递. */
#include <stdio.h>

static void report(const char *fmt, int v) {
    printf(fmt, v);
}

int main(int argc, char **argv) {
    report("count: %d\n", argc);   /* 常量格式串 */
    return 0;
}
