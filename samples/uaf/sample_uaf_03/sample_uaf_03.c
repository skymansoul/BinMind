/*
 * sample_uaf_03 — UAF with pointer alias.
 *
 * q = p; free(p); use(q).
 * q 是 p 的别名, 应被别名分析检测到.
 * CWE-416: Use After Free.
 *
 * TARPS预期: DEF_TP — A阶段确认别名, 其余阶段也确认危险
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    strcpy(p, "data");

    char *q = p;   /* 别名: q指向同一对象 */

    free(p);

    /* UAF via alias: q现在指向已释放内存 */
    q[0] = 'X';    /* A阶段: 别名追踪检测 */

    printf("done\n");
    return 0;
}
