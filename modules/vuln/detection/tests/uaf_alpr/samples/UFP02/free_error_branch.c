
/* 良性: 错误分支释放后返回, 成功路径解引用存活对象. */
#include <stdlib.h>

struct obj { int v; };
static volatile int *sink;

static void run(struct obj *o, int err) {
    if (err) {
        free(o);
        return;               /* 错误路径, 无后续 use */
    }
    sink = &o->v;             /* 成功路径, 对象存活 */
}

int main(void) {
    struct obj *o = malloc(sizeof(*o));
    run(o, 0);
    return sink != 0;
}
