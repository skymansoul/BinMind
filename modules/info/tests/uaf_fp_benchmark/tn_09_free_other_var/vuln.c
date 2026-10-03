/* UAF TN (safe) sample */
#include <stdlib.h>
typedef struct { int v; } obj_t;
int main(void) {
    obj_t *p = (obj_t *)malloc(sizeof(obj_t));
    obj_t *q = (obj_t *)malloc(sizeof(obj_t));
    if (!p || !q) return -1;
    free(q);
    p->v = 9;
    free(p);
    return 0;
}
