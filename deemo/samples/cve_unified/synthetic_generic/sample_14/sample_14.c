/*
 * sample_14 — malloc(0) 边界情况.
 *
 * malloc(0) 的行为是实现定义的:
 *   - glibc: 返回有效指针 (最小 chunk) 或 NULL
 *   - 写入任何数据都是 UB → 静态分析应标记.
 *
 * CWE-122 边界情况.
 * 此样本是非漏洞(NON-VULN): malloc(0) 在 glibc 下返回可用指针,
 * 但按 C 标准写入 malloc(0) 返回的指针是未定义行为.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *buf = (char *)malloc(0);
    if (!buf) {
        printf("malloc(0) returned NULL\n");
        return 0;
    }

    /* glibc 至少返回 16+ 可用字节, 1字节写入通常安全 */
    buf[0] = 'X';
    printf("buf[0] = %c\n", buf[0]);

    /* 但大写入会溢出 */
    memset(buf, 'Y', 256);

    free(buf);
    return 0;
}
