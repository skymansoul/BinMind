/* UAF TN (safe) sample */
#include <stdlib.h>
typedef struct { int v; } obj_t;
int main(void) {
    obj_t *p = (obj_t *)malloc(sizeof(obj_t));
    if (!p) return -1;
    free(p);
    p = (obj_t *)malloc(sizeof(obj_t));
    if (!p) return -1;
    p->v = 2;
    free(p);
    return 0;
}
