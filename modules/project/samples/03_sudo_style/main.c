/* 样本03: sudo CVE-2021-3156 模式 — 循环中的逐字节拷贝溢出
 * CVE-2021-3156: sudo Baron Samedit, 在parse_args()中将用户输入
 *   copy到栈上的固定大小user_args缓冲区, 通过逐字节循环拷贝
 * 模式: while(*src) *dst++ = *src++; 其中dst指向堆分配的固定大小buf
 * 触发条件: 源字符串长度>目标缓冲区大小, 且无长度检查
 * 为何有效: 测试检测器对循环写入和字符串操作的溢出检测能力
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SMALL_BUF 32

void vulnerable_copy(char *src) {
    char *dst = (char *)malloc(SMALL_BUF);
    if (!dst) return;
    /* 漏洞: 无长度限制的字符串拷贝, src可能任意长 */
    int i = 0;
    while (src[i]) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
    printf("copied %d bytes into %d-byte buffer\n", i, SMALL_BUF);
    free(dst);
}

int main(int argc, char **argv) {
    char input[256];
    memset(input, 'X', sizeof(input) - 1);
    input[sizeof(input) - 1] = '\0';
    if (argc > 1)
        strncpy(input, argv[1], sizeof(input) - 1);
    vulnerable_copy(input);
    return 0;
}
