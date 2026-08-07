/*
 * FP_uaf_alias_safe — 别名安全 (False Positive for TARPS Stage C).
 *
 * 场景: q=p; free(p); q=NULL; 别名q在p释放后被置NULL.
 * TARPS Stage C (别名分析) 应识别 q→p 别名关系,
 * 发现 q=NULL 使整个别名组安全.
 *
 * 预期: 基线检测器可能误报 (看到q指向已释放内存),
 *       TARPS应通过别名分析正确过滤.
 */
#include <stdio.h>
#include <stdlib.h>

typedef struct {
    int x;
    int y;
} Point;

int main() {
    Point *p = (Point *)malloc(sizeof(Point));
    if (!p) return 1;
    p->x = 10;
    p->y = 20;

    Point *q = p;  /* q是p的别名 */

    printf("x=%d y=%d\n", q->x, q->y);

    free(p);       /* 释放p → q也悬空 */
    q = NULL;      /* q置NULL → 所有别名安全 */

    /* q为NULL, 无法解引用 */
    if (q != NULL) {
        printf("x=%d\n", q->x);  /* 此路径不可达 */
    }

    return 0;
}
