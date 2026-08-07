// uaf02_basic_deref_read — 基本UAF读取
// CVE参考: CVE-UAF-DEREF-READ, 模式: uaf_deref_read
// 检测目标: free后的读取操作是否被检测
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char *buf = (char *)malloc(128);
    if (!buf) return 1;
    strcpy(buf, "sensitive_data");
    free(buf);
    // UAF: 释放后读取
    char leaked = buf[0];
    printf("leaked=%c\n", leaked);
    return 0;
}
