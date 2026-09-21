#include <stdio.h>
#include <stdlib.h>
/* INTOF-SAFE-06: 缓冲尺寸为编译期常量, 无外部输入参与长度运算 */
int main(int argc, char **argv) {
    enum { CAP = 256 };
    char buf[CAP];
    const char *mode = argc > 1 ? "user" : "default";
    snprintf(buf, sizeof(buf), "mode=%s argc=%d\n", mode, argc);
    fputs(buf, stdout);
    return 0;
}
