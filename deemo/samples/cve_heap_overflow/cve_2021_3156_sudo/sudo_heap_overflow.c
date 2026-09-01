/*
 * CVE-2021-3156 sudo 简化复现样本
 * 漏洞根因: sudo 对 argv 执行转义时, 目标缓冲区按原始长度分配,
 * 转义后实际写入长度超出分配边界, 构成堆溢出.
 */

#include <stdlib.h>
#include <string.h>

char *unescape_arg(char *src) {
    size_t l = strlen(src);
    size_t n = l + 1;
    char *dst = malloc(n);
    int w = 0;
    for (size_t i = 0; i < l; i++) {
        dst[w++] = src[i];
        if (src[i] == '\\') {
            dst[w++] = '\\';
        }
        if (src[i] == '\'') {
            dst[w++] = '\\';
        }
    }
    dst[w] = 0;
    return dst;
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    char *p = unescape_arg(argv[1]);
    free(p);
    return 0;
}
