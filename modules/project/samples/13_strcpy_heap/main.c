/* 样本13: strcpy导致的堆溢出
 * 模式: malloc(32) + strcpy(input) where input > 32 chars
 * 为何有效: 测试检测器对字符串操作(strcpy)的特殊处理
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char *buf = (char *)malloc(32);
    if (!buf) return 1;

    const char *input = argc > 1 ? argv[1] :
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBBBBBBBBB";

    /* 漏洞: strcpy无长度检查 */
    strcpy(buf, input);
    printf("strcpy %zu chars into 32B buffer\n", strlen(input));
    free(buf);
    return 0;
}
