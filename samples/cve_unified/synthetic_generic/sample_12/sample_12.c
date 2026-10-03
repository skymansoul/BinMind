/*
 * sample_12 — 多分配交互: 溢出覆盖相邻堆块.
 *
 * 漏洞: 对 buf1 的写入溢出到相邻的 buf2.
 * 这是堆 feng shui 攻击的基础 — 利用堆分配器的确定性行为
 * 精确覆盖目标 chunk.
 *
 * CWE-122.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    /* 分配两个相邻的堆块 */
    char *buf1 = (char *)malloc(32);
    char *buf2 = (char *)malloc(32);
    if (!buf1 || !buf2) return 1;

    /* 初始化 buf2 */
    strcpy(buf2, "IMPORTANT_DATA");

    /* 溢出 buf1 → 覆盖 buf2 的内容 */
    memset(buf1, 'A', 64);  /* 32 + 32 (包括 chunk header, 至少覆盖到buf2) */

    printf("buf2 = %s\n", buf2);  /* 可能被 'A' 覆盖 */
    free(buf1);
    free(buf2);
    return 0;
}
