/*
 * sample_uaf_11 — Multi-level alias chain UAF.
 *
 * p→q→r的三层别名链: r=q; q=p; free(p); use(r).
 * 别名分析需要跨越多个赋值层级.
 *
 * TARPS预期: DEF_TP — 多层别名传播检测
 * 编译: gcc -o sample_uaf_11 sample_uaf_11.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *p = (char *)malloc(128);
    if (!p) return 1;
    strcpy(p, "chain_data");

    char *q = p;   /* L1: q是p的别名 */
    char *r = q;   /* L2: r是q的别名, 间接是p的别名 */

    free(p);       /* 释放原始指针 */

    /* UAF: r→q→p 全链指向已释放内存 */
    r[0] = 'C';    /* 通过第三层别名访问 */

    printf("done\n");
    return 0;
}
