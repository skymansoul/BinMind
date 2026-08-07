/* FMT-TP-08: 用户格式串经包装函数进入 printf. */
#include <stdio.h>
#include <string.h>

void my_log(const char *fmt) {
    printf(fmt);
    printf("\n");
}

int main(int argc, char **argv) {
    char fmt[64];
    strcpy(fmt, argc > 1 ? argv[1] : "%s %d");
    my_log(fmt);
    return 0;
}
