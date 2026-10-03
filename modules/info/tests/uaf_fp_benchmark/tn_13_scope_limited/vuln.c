/* UAF TN (safe) sample */
#include <stdlib.h>
typedef struct { int v; } obj_t;
static int helper(void) {
    obj_t *t = (obj_t *)malloc(sizeof(obj_t));
    if (!t) return -1;
    int v = t->v;
    free(t);
    return v;
}
int main(void) {
    obj_t *p = (obj_t *)malloc(sizeof(obj_t));
    if (!p) return -1;
    p->v = helper();
    free(p);
    return 0;
}
