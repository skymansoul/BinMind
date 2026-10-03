/* TN 对照 4: 跨函数参数代际 — free(p) 后调用 consume(q), q 为另一
   对象 (经参数传递). 调用边界绑定使 callee 内 use 关联 q 的代际,
   与 free 对象不同. */

#include <stdio.h>
#include <stdlib.h>

struct obj {
    int v;
};

static void consume(struct obj *x) {
    printf("%d\n", x->v);
}

int main(void) {
    struct obj *p;
    struct obj *q;
    p = (struct obj *)malloc(sizeof(struct obj));
    q = (struct obj *)malloc(sizeof(struct obj));
    if (!p || !q) {
        return 1;
    }
    p->v = 1;
    q->v = 2;
    free(p);
    consume(q);
    free(q);
    return 0;
}
