
/* 良性: free 后重绑定新分配 — 指针指向新对象, 非 UAF. */
#include <stdlib.h>

struct obj { int v; };
static volatile int *sink;

int main(void) {
    struct obj *p = malloc(sizeof(*p));
    free(p);
    p = malloc(sizeof(*p));   /* 重绑定新分配 */
    sink = &p->v;             /* 解引用新对象 */
    return sink != 0;
}
