/*
 * sample_uaf_02 — UAF with NULL guard (误报测试).
 *
 * free(p) 后 p = NULL, 然后在 if(p) 内 use(p).
 * 这是误报: NULL检查阻止了UAF利用.
 * CWE-416: Use After Free.
 *
 * TARPS预期: DEF_FP / LIKELY_FP — T阶段确认NULL置零, P阶段确认if守卫
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *buf = (char *)malloc(128);
    if (!buf) return 1;
    strcpy(buf, "hello");

    free(buf);
    buf = NULL;  /* T阶段: NULL置零 */

    /* P阶段: if守卫 — 不会对NULL指针解引用 */
    if (buf != NULL) {
        buf[0] = 'x';  /* 死代码, 永不执行 */
    }

    printf("safe\n");
    return 0;
}
