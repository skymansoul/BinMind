/*
 * TP_uaf_loop_use — 循环内的Use-After-Free。
 *
 * 场景: free(p)后在循环内继续使用p, 无保护.
 * 预期: UAF检测器应检出 (TRUE POSITIVE).
 *
 * CWE-416: Use After Free
 */
#include <stdio.h>
#include <stdlib.h>

typedef struct {
    int items[10];
    int count;
} Buffer;

int main() {
    Buffer *buf = (Buffer *)malloc(sizeof(Buffer));
    if (!buf) return 1;

    for (int i = 0; i < 10; i++) {
        buf->items[i] = i * 10;
    }
    buf->count = 10;

    free(buf);  /* 释放 */

    /* UAF: 循环内继续使用已释放指针 */
    for (int i = 0; i < 10; i++) {
        printf("item[%d]=%d\n", i, buf->items[i]);  /* ← UAF HERE */
    }

    return 0;
}
