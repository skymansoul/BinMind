/* heap_overflow_04 — 循环内的渐进式堆溢出
 *
 * 循环中 strcat 不检查总长度, 逐步越过分配边界.
 * 测试检测器对跨基本块、依赖循环分析的溢出检测.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *buf = (char *)malloc(32);
    if (!buf) return 1;
    buf[0] = '\0';

    /* BUG: 循环内 strcat, 每次追加 10 bytes,
     *       第4次时超出 32 bytes 分配 */
    const char *chunks[] = {"AAAAAAAAAA", "BBBBBBBBBB",
                            "CCCCCCCCCC", "DDDDDDDDDD",
                            "EEEEEEEEEE", "FFFFFFFF"};

    for (int i = 0; i < 6; i++) {
        strcat(buf, chunks[i]);
        printf("after chunk %d: len=%zu\n", i, strlen(buf));
    }

    free(buf);
    return 0;
}
