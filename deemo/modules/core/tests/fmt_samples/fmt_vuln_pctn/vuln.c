/*
 * FMT-VULN-PCTN — 常量格式串含 %n 写说明符
 * printf("...%n", &x) 把已写字符数写入变量, 可作任意写原语.
 * 触发: banner 常量串含 %n, 目标为栈变量.
 */
#include <stdio.h>

int main(void) {
    int written = 0;
    /* 漏洞: %n 写说明符 */
    printf("processing item %n", &written);
    printf("\n%d\n", written);
    return 0;
}
