
/* 良性: 使用发生在释放之前. */
#include <stdlib.h>

struct obj { int v; };
static volatile int *sink;

int main(void) {
    struct obj *o = malloc(sizeof(*o));
    sink = &o->v;             /* use 在前 */
    free(o);                  /* free 在后 */
    return sink != 0;
}
