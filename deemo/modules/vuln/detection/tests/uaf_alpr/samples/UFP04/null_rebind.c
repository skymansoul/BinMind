
/* 良性: free 后置 NULL 并判空使用 — 空指针路径不触碰释放内存. */
#include <stdlib.h>

struct obj { int v; };
static volatile int *sink;

int main(void) {
    struct obj *p = malloc(sizeof(*p));
    free(p);
    p = 0;                    /* 重绑定为常量 */
    if (p) sink = &p->v;      /* 不可达解引用 */
    return 0;
}
