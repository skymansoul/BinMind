
/* 良性: 释放堆对象, 解引用独立栈对象 — 无共享生命周期. */
#include <stdlib.h>

struct heap_obj { int h; };
struct stack_obj { int s; };
static volatile int *sink;

int main(void) {
    struct heap_obj *h = malloc(sizeof(*h));
    struct stack_obj st;
    free(h);
    sink = &st.s;             /* 解引用独立栈对象 */
    return sink != 0;
}
