/* TN 对照 5: 时序安全 — use(p) 在 free(p) 之前 (地址序 use < free).
   时序判定 DEFINITELY_SAFE, 不构成 UAF. */

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
    printf("%d\n", p->v);
    free(p);
    return 0;
}
