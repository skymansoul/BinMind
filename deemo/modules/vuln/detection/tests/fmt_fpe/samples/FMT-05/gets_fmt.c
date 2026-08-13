
/* 格式串漏洞复现: gets 读取内容作 printf 格式串. */
#include <stdio.h>

int main(void) {
    char buf[256];
    gets(buf);               /* 用户输入 */
    printf(buf);             /* 格式串 = 用户输入 */
    return 0;
}
