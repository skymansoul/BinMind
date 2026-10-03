/*
 * sample_18 — memmove 堆溢出 (重叠拷贝变体).
 *
 * 漏洞: memmove 的 size 参数来自用户输入,
 * 超过了目标缓冲区的实际大小.
 *
 * 与 memcpy 的区别: memmove 处理重叠区域,
 * 静态分析器需要同样追踪其 size 参数.
 *
 * CWE-122.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *src = (char *)malloc(256);
    char *dst = (char *)malloc(64);
    if (!src || !dst) return 1;

    memset(src, 'S', 256);

    /* memmove 的 size 参数 (256) > dst 大小 (64) → 溢出 */
    memmove(dst, src, 256);

    printf("dst[0] = %c\n", dst[0]);
    free(src);
    free(dst);
    return 0;
}
