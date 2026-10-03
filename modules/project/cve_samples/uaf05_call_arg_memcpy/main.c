// uaf05_call_arg_memcpy — 函数调用参数UAF
// CVE参考: CVE-UAF-CALL-ARG, 模式: uaf_call_arg_dst
// 检测目标: 悬挂指针作为函数参数 (第一个参数=目标缓冲区) 传递给memcpy
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char *buf = (char *)malloc(128);
    if (!buf) return 1;
    memset(buf, 0, 128);
    free(buf);
    // UAF: 悬挂指针作为memcpy的目标
    memcpy(buf, "overflow", 9);
    printf("UAF memcpy: %s\n", buf);
    return 0;
}
