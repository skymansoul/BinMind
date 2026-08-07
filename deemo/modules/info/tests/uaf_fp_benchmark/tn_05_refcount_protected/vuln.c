/* UAF TN (safe) sample */
#include <stdlib.h>
typedef struct { int refs; int v; } obj_t;
int main(void) {
    obj_t *p = (obj_t *)malloc(sizeof(obj_t));
    if (!p) return -1;
    p->refs = 2;
    if (--p->refs == 0) { free(p); }
    if (p->refs > 0) { p->v = 5; }
    if (--p->refs == 0) { free(p); }
    return 0;
}
