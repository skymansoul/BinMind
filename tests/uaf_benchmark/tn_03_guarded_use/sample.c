/* TN-03: Guarded Use with refcount (SAFE) */
#include <stdlib.h>
typedef struct { int refcount; char *data; } obj_t;
void guarded_free(obj_t *obj) {
    if (obj->refcount > 0) { obj->refcount--; return; }
    free(obj->data); obj->data = NULL;
}
void guarded_use(obj_t *obj) {
    if (obj && obj->data) { obj->data[0] = 'A'; }
}
int main(void) {
    obj_t *obj = (obj_t *)malloc(sizeof(obj_t));
    obj->refcount = 1;
    obj->data = (char *)malloc(32);
    guarded_free(obj); guarded_use(obj);
    free(obj->data); free(obj); return 0;
}