
/* 格式串漏洞复现: read 读取内容作 printf 格式串. */
#include <stdio.h>
#include <unistd.h>

int main(void) {
    char buf[128];
    int n = read(0, buf, 127);
    buf[n] = 0;
    printf(buf);             /* 格式串 = 网络/管道输入 */
    return 0;
}
