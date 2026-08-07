/* UAF TP sample */
#include <stdlib.h>
typedef struct { int f; } obj_t;
int main(void) {
    obj_t *p = (obj_t *)malloc(sizeof(obj_t));
    if (!p) return -1;
    obj_t *q = p;
    free(p);
    q->f = 2;
    return 0;
}
