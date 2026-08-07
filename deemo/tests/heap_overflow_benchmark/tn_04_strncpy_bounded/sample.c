/*
 * TN-04: strncpy with Correct Bound (NO OVERFLOW)
 *
 * malloc(128) → strncpy(buf, src, 127) → 有界拷贝且size < alloc
 * 拷贝上限127B < 分配128B → 安全
 *
 * 正则检测器可能误报: 任何strncpy/strcpy类函数都标记
 * LPVRA应判定: SAFE → FILTER (strncpy bound=127 + chunk_slack < alloc_lo=128)
 */
#include <stdlib.h>
#include <string.h>

int safe_strncpy(const char *src) {
    char *buf = (char *)malloc(128);
    if (!buf) return -1;

    /* strncpy限制拷贝上限, 且 < 分配大小 */
    strncpy(buf, src, 127);
    buf[127] = '\0';  /* 手动终止, 在边界内 */

    free(buf);
    return 0;
}

int main(void) {
    return safe_strncpy("short string");
}
