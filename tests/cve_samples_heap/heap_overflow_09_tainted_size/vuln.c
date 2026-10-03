/* 污点传播: atoi用户输入→malloc→memcpy
 * alloc=n(用户控制可达INT_MAX), write=m(另一个用户控制)
 * 预期: 检测器追踪n和m的关系, n<m时溢出
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

void handle(int n, int m, const char *src) {
    if (n <= 0) n = 1;
    char *buf = (char*)malloc(n);
    /* 漏洞: m可能>n */
    memcpy(buf, src, m);
    free(buf);
}

int main() {
    char src[4096];
    memset(src, 'T', 4096);
    handle(64, 4096, src);  /* m >> n */
    return 0;
}
