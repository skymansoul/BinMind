/* 样本11: 堆上的Off-by-One
 * 模式: malloc(strlen(str))但未+1给null terminator
 * CVE参考: CVE-2016-6309 (OpenSSL: off-by-one in DTLS)
 * 触发条件: strlen返回的值未包含'\0', 分配少1字节
 * 为何有效: 测试检测器对边界情况的敏感度
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    const char *input = argc > 1 ? argv[1] : "HelloWorld1234567890";
    size_t len = strlen(input);

    /* 漏洞: 分配len字节但strcpy写len+1字节('\0') */
    char *buf = (char *)malloc(len);
    if (!buf) return 1;

    strcpy(buf, input);  /* 写入 len+1 字节 (包含'\0') */
    printf("malloc(%zu) strcpy(%zu+1 bytes)\n", len, len);
    free(buf);
    return 0;
}
