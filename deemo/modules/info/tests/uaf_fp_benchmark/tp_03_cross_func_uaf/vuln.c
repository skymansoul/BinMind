/* UAF TP sample */
#include <stdlib.h>
typedef struct { int v; } obj_t;
static void touch(obj_t *o) { o->v = 3; }
int main(void) {
    obj_t *p = (obj_t *)malloc(sizeof(obj_t));
    if (!p) return -1;
    free(p);
    touch(p);
    return 0;
}
