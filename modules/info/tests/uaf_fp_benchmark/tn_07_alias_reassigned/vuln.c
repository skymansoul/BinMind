/* UAF TN (safe) sample */
#include <stdlib.h>
typedef struct { int v; } obj_t;
int main(void) {
    obj_t *p = (obj_t *)malloc(sizeof(obj_t));
    if (!p) return -1;
    obj_t *q = p;
    free(p);
    q = (obj_t *)malloc(sizeof(obj_t));
    if (!q) return -1;
    q->v = 7;
    free(q);
    return 0;
}
