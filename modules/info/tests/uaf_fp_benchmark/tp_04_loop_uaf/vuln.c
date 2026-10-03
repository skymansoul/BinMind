/* UAF TP sample */
#include <stdlib.h>
typedef struct { int v; } obj_t;
int main(void) {
    obj_t *p = (obj_t *)malloc(sizeof(obj_t));
    if (!p) return -1;
    int i;
    for (i = 0; i < 3; i++) {
        if (i == 1) { free(p); }
        p->v = i;
    }
    return 0;
}
