
/* 良性: 常量格式串经局部变量传递, 距调用点超过回溯窗口. */
#include <stdio.h>

int main(int argc, char **argv) {
    const char *fmt = "value: %d\n";
    int sum = 0;
    for (int i = 0; i < argc; i++) sum += i;   /* 插入指令 */
    sum += argc;
    printf(fmt, sum);        /* fmt 为局部常量引用 */
    return sum != 0;
}
