/* 假阳性测试 — 充分边界检查, 不应报告为漏洞 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void safe_copy(const char *input, size_t input_len) {
    size_t alloc_sz = (input_len + 16 + 15) & ~15; /* 对齐到 16B */
    char *buf = (char *)malloc(alloc_sz);
    if (!buf) return;
    /* 安全: memcpy 使用 input_len, alloc_sz >= input_len */
    memcpy(buf, input, input_len);
    buf[input_len] = '\0';
    printf("%s\n", buf);
    free(buf);
}

int main(void) {
    safe_copy("short string", 12);
    return 0;
}
