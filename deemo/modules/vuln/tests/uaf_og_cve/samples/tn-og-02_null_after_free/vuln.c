/* TN 对照 2: NULL 置位 — free(p); p = NULL; if (p) use(p).
   null-after-free 是最强安全信号, 代际置 NULL 后压制. */

#include <stdio.h>
#include <stdlib.h>

struct obj {
    int v;
};

int main(void) {
    struct obj *p;
    p = (struct obj *)malloc(sizeof(struct obj));
    if (!p) {
        return 1;
    }
    p->v = 1;
    free(p);
    p = NULL;
    if (p) {
        printf("%d\n", p->v);
    }
    return 0;
}
