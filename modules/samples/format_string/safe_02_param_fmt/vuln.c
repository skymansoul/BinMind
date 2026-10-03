/*
 * 格式化字符串安全对照 B — 参数化格式化 (TN)
 * 目标: 验证 fmt 来自常量数组/函数参数但不含 % 时不误报
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *get_fmt(void) {
    /* 固定格式串, 无转换符 */
    return "operation completed";
}

int main(int argc, char **argv) {
    const char *fmt = get_fmt();
    printf("%s", fmt);   /* 安全: 静态串经 %s 输出 */
    printf(fmt);         /* 安全: fmt 无转换符 */
    return 0;
}
