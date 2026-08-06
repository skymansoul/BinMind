/* stack_overflow_01 — gets() 无边界检查
 * 对应 CWE-121: Stack-based Buffer Overflow
 * 编译: gcc -o vuln vuln.c -fno-stack-protector
 */
#include <stdio.h>
#include <string.h>

void vuln() {
    char buf[64];
    gets(buf);  /* 危险: gets 不检查边界, 输入>64B 覆盖返回地址 */
    printf("you said: %s\n", buf);
}

int main() {
    vuln();
    return 0;
}
