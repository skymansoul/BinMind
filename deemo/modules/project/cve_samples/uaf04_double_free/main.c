// uaf04_double_free — 双重释放
// CVE参考: CVE-UAF-DOUBLE-FREE, 模式: double_free
// 检测目标: 同一寄存器中的指针被free两次
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char *buf = (char *)malloc(128);
    if (!buf) return 1;
    free(buf);
    // UAF: 双重释放
    free(buf);
    printf("double free: %p\n", (void *)buf);
    return 0;
}
