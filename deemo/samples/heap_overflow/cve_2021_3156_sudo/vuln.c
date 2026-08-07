/* CVE-2021-3156 — Sudo Baron Samedit (simplified heap overflow pattern)
 * 原始漏洞: sudoedit 解析命令行参数时, 未正确处理转义反斜杠,
 *   导致堆溢出. 漏洞点在 set_cmnd() 函数中.
 * 本文件简化为核心模式: 字符串拼接未考虑转义后长度变化.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* 模拟: 转义处理导致字符串变长, 但分配时未考虑转义后的额外字符 */
char *escape_and_copy(const char *src) {
    size_t src_len = strlen(src);
    /* bug: 只为原长度分配, 但转义后每个 \ 后面多一个字符 */
    char *dst = (char *)malloc(src_len + 1);
    if (!dst) return NULL;
    size_t di = 0;
    for (size_t si = 0; si < src_len; si++) {
        if (src[si] == '\\') {
            dst[di++] = '\\'; /* overflow if di >= src_len */
        }
        dst[di++] = src[si]; /* overflow for each escaped char */
    }
    dst[di] = '\0';
    return dst;
}

int main(void) {
    /* input contains many backslashes → escaped output > allocated */
    char *result = escape_and_copy("\\\\\\AAAAAAAAAAAAAAAAAAAAAAAAAAA");
    if (result) {
        printf("%s\n", result);
        free(result);
    }
    return 0;
}
