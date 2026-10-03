
/* 良性: realloc 迁移后解引用新指针 — 旧块未再使用. */
#include <stdlib.h>

struct obj { int v; };
static volatile int *sink;

int main(void) {
    struct obj *p = malloc(sizeof(*p));
    struct obj *np = realloc(p, 2 * sizeof(*p)); /* 返回新块 */
    sink = &np->v;            /* 解引用新指针 */
    return sink != 0;
}
