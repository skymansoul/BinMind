/*
 * sample_16 — realloc 返回NULL后的堆溢出.
 *
 * 漏洞: realloc 失败返回 NULL, 但原始指针未被释放,
 * 代码继续使用原始指针 → 可能写入已释放的内存 (UAF + overflow).
 *
 * 此样本测试同时涉及 realloc 和 overflow 的复杂场景.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *buf = (char *)malloc(64);
    if (!buf) return 1;

    /* 尝试 realloc 到一个巨大的 size (可能失败) */
    char *new_buf = (char *)realloc(buf, (size_t)-1);
    if (!new_buf) {
        /* realloc 失败, buf 仍然有效 (未被释放) */
        /* 但后续代码可能不知道, 继续用旧 size ... 这不是溢出 */
        printf("realloc failed, buf still valid\n");
        memset(buf, 'Z', 64);  /* 安全 */
    } else {
        buf = new_buf;
    }

    /* 实际溢出: 写入超过原始分配 */
    memset(buf, 'Z', 256);  /* 溢出! */

    printf("buf[0] = %c\n", buf[0]);
    free(buf);
    return 0;
}
