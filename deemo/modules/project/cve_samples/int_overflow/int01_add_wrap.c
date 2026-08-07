// int01_add_wrap: 无符号加法回绕 → 边界检查被绕过
// 模式: 用户输入size, 加上固定偏移后回绕, 绕过边界检查
// 预期检测: Mode 1 (UADD_WRAP) — add回绕
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    unsigned int size = 0xFFFFFFF0;
    if (argc > 1) size = (unsigned int)atoi(argv[1]);

    // 漏洞: size + 32 可能回绕 (当 size > 0xFFFFFFE0)
    // size = 0xFFFFFFF8 时, size + 32 = 0x00000018 (回绕)
    unsigned int padded = size + 32;
    char *buf = (char *)malloc(padded);
    if (!buf) return 1;

    // 如果回绕了, padded 远小于 size, memcpy 会溢出
    memcpy(buf, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", size);
    printf("copied %u bytes to %u-byte buffer\n", size, padded);
    free(buf);
    return 0;
}
