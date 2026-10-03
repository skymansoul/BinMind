/* TN 对照 1: 重赋值推进代际 — free(p); p = q; use(p).
   旧检测器把 free 后的任何 use 报为 UAF; 代际分析判定 p 已指向
   新对象 gen2, 压制. */

#include <stdio.h>
#include <stdlib.h>

struct obj {
    int v;
};

int main(void) {
    struct obj *p;
    struct obj *q;
    p = (struct obj *)malloc(sizeof(struct obj));
    q = (struct obj *)malloc(sizeof(struct obj));
    if (!p || !q) {
        return 1;
    }
    p->v = 1;
    free(p);
    p = q;
    p->v = 2;
    printf("%d\n", p->v);
    free(q);
    return 0;
}
