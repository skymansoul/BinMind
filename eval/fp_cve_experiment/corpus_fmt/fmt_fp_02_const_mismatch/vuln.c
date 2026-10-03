/* 安全: 常量格式串, 参数缺失 — 属参数错误, 非格式化字符串漏洞. */
#include <stdio.h>

int main(void) {
    printf("%s %d\n", "only-one");
    return 0;
}
